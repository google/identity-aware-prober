# Identity Aware Prober

Identity Aware Prober (iaprober) is a binary intended to be used as an external
server-mode probe for use with [Cloudprober](https://cloudprober.org/) for probing pages
behind Google Cloud's [Identity Aware Proxy (IAP)](https://cloud.google.com/iap/).

The binary reads GCP service account credentials from a local JSON file. That service
account must have read access to the IAP-protected page.

DISCLAIMER: This is not an officially supported Google product

## How to use iaprober

The easiest way to use iaprober is to run it alongside Cloudprober in Docker,
in Google Kubernetes Engine. Note: the following commands enable chargeable APIs
and services on Google Cloud Platform.

The following assumes you have an existing Google Cloud project.

To create a new service account, follow the instructions for [creating a new
service
account](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances).
Grant this service account permission to access any IAP-protected page that you
want to test.

To create a new Kubernetes cluster, following the instructions for [creating a
cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-cluster).
This will also configure your local kubectl command.

Download the service account's credentials as a .json file, following the
instructions at [creating and managing service account
keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys).

Put the credentials in a file named `auth.json`. Upload this to your Kubernetes
cluster as a secret:

```
kubectl create secret generic service-account  --from-file=auth.json
```
or use the Makefile:
```
make auth
```


Create a file containing your list of targets. The lines of this file contain
space-separated parameters:

1. A short-name for the page you are testing
1. The OAuth client-id for the IAP page. This can be found on the
   [IAP page](https://console.cloud.google.com/security/iap/) of
   https://console.cloud.google.com
1. The URL of the page to be probed

This file should be uploaded as a Kubernetes ConfigMap resource:

```
kubectl create configmap targets --from-file=targets
```
or use the Makefile:
```
make targets
```

Create the iaprober binary. Because the binary image will be copied to the
Cloudprober container, and the Cloudprober container is based upon Busybox, we
won't have shared libraries available. The makefile specifies the necessary
build flags to create a static binary that will work on Busybox.

```
make iaprober
```

Create the Docker image that will contain the iaprober binary (specifying your
project name):

```
gcloud container builds submit --tag=gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober  .
```

You may be prompted to enable the container builder APIs on your project.

Add the `live` tag to the container image:

```
gcloud container images add-tag gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober:live
```

Modify the k8s/cloudprober.yaml file to change the Deployment spec image for the
iaprober container to `gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober:live`

Deploy the service and expose the Prometheus metrics port:

```
kubectl apply -f cloudprober.yaml
```

To verify that it is working, find the external IP address for the service:

```
kubectl get service/cloudprober-service
```

And verify that metrics are appearing:

```
curl "http://${IP_ADDRESS}:9313/metrics"
```

If you do not need the Prometheus metrics, comment out the Service resource from
cloudprober.yaml, and run `kubectl apply -f cloudprober.yaml`

## Running iaprober manually

If running cloudprober manually, you'll need the iaprober binary, and the
service account credentials available locally. Modify the following
`cloudprober.cfg` file as appropriate:

```
probe {
  name: "probe_name"
  type: EXTERNAL
  targets { dummy_targets {} }
  external_probe {
    mode: SERVER
    command: "/path/to/iaprober --server --credentials=/path/to/credentials/auth.json"
    options: {
      name: "url"
      value: "https://example.com"
    }
    options: {
      name: "client_id"
      value: "OAuth-client-id-string"
    }
  }
  interval_msec: 5000  # 5s
  timeout_msec: 1000   # 1s
}
```

And run cloudprober with:

```
cloudprober --config_file=cloudprober.cfg
```

And verify that it is working by checking the metrics page:

```
curl "http://localhost:9313/metrics"
```

## Running a single probe

For a one-off test you can run iaprober from the command line. You will need the
service account JSON credentials, the OAuth client ID of the IAP page, and the
URL:

```
iaprober --credentials=/path/to/credentials/auth.json \
--url=https://example.com \
--clientid=OAuth-client-id-string 
```
