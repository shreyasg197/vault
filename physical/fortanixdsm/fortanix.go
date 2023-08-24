package fortanix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	"github.com/fortanix/sdkms-client-go/sdkms"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/physical"
)

type fortanixBackend struct {
	client     *sdkms.Client
	apiKey     string
	endpoint   string
	prefix     string
	logger     log.Logger
	permitPool *physical.PermitPool
}

var defaultKeyOps = someKeyOperations(
	sdkms.KeyOperationsAppmanageable | sdkms.KeyOperationsExport,
)

func NewFortanixBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	apiKey := os.Getenv("FORTANIX_APIKEY")
	if apiKey == "" {
		apiKey = conf["apikey"]
		if apiKey == "" {
			return nil, fmt.Errorf("'apikey' must be set")
		}
	}
	endpoint := os.Getenv("FORTANIX_ENDPOINT")
	if endpoint == "" {
		endpoint = conf["endpoint"]
		if endpoint == "" {
			return nil, fmt.Errorf("'endpoint' must be set")
		}
	}

	prefix := os.Getenv("FORTANIX_PREFIX")
	if prefix == "" {
		prefix = conf["prefix"]
		if prefix == "" {
			return nil, fmt.Errorf("'prefix' must be set")
		}
	}

	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth:       sdkms.APIKey(apiKey),
		Endpoint:   endpoint,
	}

	maxParStr, ok := conf["max_parallel"]
	var maxParInt int
	if ok {
		maxParInt, err := strconv.Atoi(maxParStr)
		if err != nil {
			return nil, fmt.Errorf("failed parsing max_parallel parameter: %w", err)
		}
		if logger.IsDebug() {
			logger.Debug("max_parallel set", "max_parallel", maxParInt)
		}
	}

	return &fortanixBackend{
		client:     &client,
		apiKey:     apiKey,
		endpoint:   endpoint,
		logger:     logger,
		prefix:     prefix,
		permitPool: physical.NewPermitPool(maxParInt),
	}, nil
}

func (b *fortanixBackend) Put(ctx context.Context, entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"fortanix", "put"}, time.Now())

	b.permitPool.Acquire()
	defer b.permitPool.Release()

	// Setup key
	Key := addPrefix(entry.Key, b.prefix)

	sobjectReq := sdkms.SobjectRequest{
		Name:    &Key,
		ObjType: someObjectType(sdkms.ObjectTypeSecret),
		KeyOps:  defaultKeyOps,
		Value:   &entry.Value,
	}

	_, err := b.client.ImportSobject(ctx, sobjectReq)
	if err != nil {
		var e *sdkms.BackendError
		if errors.As(err, &e) {
			// for 409, we rotate the object with new value
			if e.StatusCode == 409 {
				deactivateOldKey := true
				sobjRotateRequest := sdkms.SobjectRekeyRequest{
					DeactivateRotatedKey: &deactivateOldKey,
					Dest:                 sobjectReq,
				}
				_, err := b.client.RotateSobject(ctx, sobjRotateRequest)
				// we expect this to succeed, report errors here
				if err != nil {
					return err
				}
			} else {
				// we hit an error and it's not 409
				return err
			}
		}
	}
	return nil
}

func (b *fortanixBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"fortanix", "get"}, time.Now())

	b.permitPool.Acquire()
	defer b.permitPool.Release()

	// Setup key
	Key := addPrefix(key, b.prefix)

	sobjectDescriptor := sdkms.SobjectDescriptor{
		Name: &Key,
	}
	sobject, err := b.client.ExportSobject(ctx, sobjectDescriptor)
	if err != nil {
		var e *sdkms.BackendError
		if errors.As(err, &e) {
			if e.StatusCode == 404 {
				// 404 means we couldn't find the key, not an error for GET
				return nil, nil
			}
		}
		// we have an error and it's not 404
		return nil, err
	}
	value := sobject.Value
	data := bytes.NewBuffer(*value)

	ent := &physical.Entry{
		Key:   key,
		Value: data.Bytes(),
	}
	return ent, nil
}

func (b *fortanixBackend) Delete(ctx context.Context, key string) error {
	defer metrics.MeasureSince([]string{"fortanix", "delete"}, time.Now())

	b.permitPool.Acquire()
	defer b.permitPool.Release()

	Key := addPrefix(key, b.prefix)
	sobjDescriptor := sdkms.SobjectDescriptor{
		Name: &Key,
	}

	sobject, err := b.client.GetSobject(ctx, nil, sobjDescriptor)
	if err != nil {
		var e *sdkms.BackendError
		if errors.As(err, &e) {
			if e.StatusCode == 404 {
				// 404 means we couldn't find the key, don't report as error
				return nil
			}
		}
		// we have an error and it's not 404
		return err
	}

	err = b.client.DeleteSobject(ctx, *sobject.Kid)
	if err != nil {
		// We expect this to succeed, report errors here
		return err
	}
	return nil
}

// func (b *fortanixBackend) List(ctx context.Context, prefix string) ([]string, error) {
// 	defer metrics.MeasureSince([]string{"fortanix", "list"}, time.Now())
//
// 	b.permitPool.Acquire()
// 	defer b.permitPool.Release()
//
// 	prefix = addPrefix(prefix, b.prefix)
// 	keys := []string{}
//
// 	// filter for DSM
// 	activeWithName := `{"$and":[{"state":{"$in":["Active"]}},{"name":{"$text":{"$search":"` + prefix + `"}}}]}`
//
// 	withMetadata := true
// 	queryParams := sdkms.ListSobjectsParams{
// 		Filter: &activeWithName,
// 		Sort: &sdkms.SobjectSort{
// 			ByName: &sdkms.SobjectSortByName{},
// 		},
// 		WithMetadata: &withMetadata,
// 	}
// 	sobjs, err := b.client.ListSobjects(ctx, &queryParams)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	if sobjs.Items != nil {
// 		for _, sobj := range sobjs.Items {
// 			key := strings.TrimPrefix(*sobj.Name, prefix)
// 			if i := strings.Index(key, "/"); i == -1 {
// 				// we found the key
// 				keys = append(keys, key)
// 			} else {
// 				// subdirectory
// 				keys = strutil.AppendIfMissing(keys, key[:i+1])
// 			}
// 		}
// 	}
//
// 	sort.Strings(keys)
// 	return keys, nil
// }
//



func (b *fortanixBackend) List(ctx context.Context, prefix string) ([]string, error) {
    defer metrics.MeasureSince([]string{"fortanix", "list"}, time.Now())

    b.permitPool.Acquire()
    defer b.permitPool.Release()

    prefix = addPrefix(prefix, b.prefix)
    keys := []string{}

    // Filter for DSM
    activeWithName := `{"$and":[{"state":{"$in":["Active"]}},{"name":{"$text":{"$search":"` + prefix + `"}}}]}`

    withMetadata := true
    queryParams := sdkms.ListSobjectsParams{
        Filter: &activeWithName,
        Sort: &sdkms.SobjectSort{
            ByName: &sdkms.SobjectSortByName{},
        },
        WithMetadata: &withMetadata,
    }
    sobjs, err := b.client.ListSobjects(ctx, &queryParams)
    if err != nil {
        return nil, err
    }

    if sobjs.Items != nil {
        for _, sobj := range sobjs.Items {
            key := strings.TrimPrefix(*sobj.Name, prefix)
            if i := strings.Index(key, "/"); i == -1 {
                // we found the key
                keys = append(keys, key)
            } else {
                // subdirectory
                keys = strutil.AppendIfMissing(keys, key[:i+1])
            }
        }
    }

    // List all sobjects
    allQueryParams := sdkms.ListSobjectsParams{
        Sort: &sdkms.SobjectSort{
            ByKid: &sdkms.SobjectSortByKid{},
        },
    }
    allSobjects, err := b.client.ListSobjects(ctx, &allQueryParams)
    if err != nil {
        return nil, err
    }

    allKeys := []string{}
    for _, sobj := range allSobjects.Items {
        key := strings.TrimPrefix(*sobj.Name, prefix)
        if i := strings.Index(key, "/"); i == -1 {
            allKeys = append(allKeys, key)
        } else {
            allKeys = strutil.AppendIfMissing(allKeys, key[:i+1])
        }
    }

    keys = append(keys, allKeys...)

    sort.Strings(keys)
    return keys, nil
}



func addPrefix(key string, prefix string) string {
	// if !strings.HasPrefix(key,"logical") {
	key = prefix + "-" + key
	// }
	return key
}
func someObjectType(val sdkms.ObjectType) *sdkms.ObjectType          { return &val }
func someKeyOperations(val sdkms.KeyOperations) *sdkms.KeyOperations { return &val }
