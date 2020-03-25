var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instancesMultiAz');

const createCache = (instanceData, instanceDatab, instanceGroupData, error, iGErr) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    },
                    'us-central1-b': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-c': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-f': {
                        data: instanceDatab,
                        err: error
                    }
                }
            }
        },
        instanceGroups: {
            aggregatedList: {
                'global': {
                    data: instanceGroupData,
                    err: iGErr
                }
            }
        }
    }
}

describe('instancesMultiAz', function () {
    describe('run', function () {
        it('should return unknown if an instance group error or no data returned', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instance groups');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
                null,
                ['error'],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });
        it('should return unknown if an instance error or no data returned', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(3);
                expect(results[4].message).to.include('Unable to query instances');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null,
                ['hellooo']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no VM Instances found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('No instances found');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                [],
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if instances are available in only one zone', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(2);
                expect(results[4].message).to.include('These instances are only available in one zone');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: '567091234322-compute@developer.gserviceaccount.com',
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                [],
                {
                    "regions/us-central1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-central1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-central1"
                                }
                            ]
                        }
                    },
                    "regions/europe-west1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west1"
                                }
                            ]
                        }
                    },
                    "regions/us-west1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-west1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-west1"
                                }
                            ]
                        }
                    },
                    "regions/asia-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-east1"
                                }
                            ]
                        }
                    },
                    "regions/us-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-east1"
                                }
                            ]
                        }
                    },
                    "regions/asia-northeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-northeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-northeast1"
                                }
                            ]
                        }
                    },
                    "regions/asia-southeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-southeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-southeast1"
                                }
                            ]
                        }
                    },
                    "regions/us-east4": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-east4' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-east4"
                                }
                            ]
                        }
                    },
                    "regions/australia-southeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/australia-southeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/australia-southeast1"
                                }
                            ]
                        }
                    },
                    "regions/europe-west2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west2"
                                }
                            ]
                        }
                    },
                    "regions/europe-west3": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west3' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west3"
                                }
                            ]
                        }
                    },
                    "regions/southamerica-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/southamerica-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/southamerica-east1"
                                }
                            ]
                        }
                    },
                    "regions/asia-south1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-south1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-south1"
                                }
                            ]
                        }
                    },
                    "regions/northamerica-northeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/northamerica-northeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/northamerica-northeast1"
                                }
                            ]
                        }
                    },
                    "regions/europe-west4": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west4' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west4"
                                }
                            ]
                        }
                    },
                    "regions/europe-north1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-north1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-north1"
                                }
                            ]
                        }
                    },
                    "regions/us-west2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-west2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-west2"
                                }
                            ]
                        }
                    },
                    "regions/asia-east2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-east2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-east2"
                                }
                            ]
                        }
                    },
                    "regions/europe-west6": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west6' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west6"
                                }
                            ]
                        }
                    },
                    "regions/asia-northeast2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-northeast2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-northeast2"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-a": {
                        "instanceGroups": [
                            {
                                "id": "8174056737747537683",
                                "creationTimestamp": "2019-12-17T11:52:28.215-08:00",
                                "name": "gke-standard-cluster-1-default-pool-dbd4f731-grp",
                                "description": "This instance group is controlled by Instance Group Manager 'gke-standard-cluster-1-default-pool-dbd4f731-grp'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                "network": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/global/networks/default",
                                "fingerprint": "42WmSpB8rSM=",
                                "zone": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a",
                                "selfLink": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a/instanceGroups/gke-standard-cluster-1-default-pool-dbd4f731-grp",
                                "size": 1,
                                "subnetwork": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/subnetworks/default",
                                "kind": "compute#instanceGroup"
                            }
                        ]
                    },
                    "zones/us-central1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-f": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-f' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-f"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-d": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-d' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-d"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-d": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-d' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-d"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-a"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-b"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-c"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-b"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-a"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-c"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-c"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-b"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-a"
                                }
                            ]
                        }
                    }
                },
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if the instance groups in the region are highly available', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('The instance groups in the region are highly available');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "1590799577276483925",
                        "creationTimestamp": "2020-01-02T11:04:27.612-08:00",
                        "name": "test-instance-group-1-dqfb",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "machineType": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a",
                        "canIpForward": false,
                        "networkInterfaces": [
                            {
                                "network": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/global/networks/default",
                                "subnetwork": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/subnetworks/default",
                                "networkIP": "10.128.0.25",
                                "name": "nic0",
                                "accessConfigs": [
                                    {
                                        "type": "ONE_TO_ONE_NAT",
                                        "name": "External NAT",
                                        "natIP": "146.148.108.253",
                                        "networkTier": "PREMIUM",
                                        "kind": "compute#accessConfig"
                                    }
                                ],
                                "fingerprint": "hwy2jYrdaXM=",
                                "kind": "compute#networkInterface"
                            }
                        ],
                        "disks": [
                            {
                                "type": "PERSISTENT",
                                "mode": "READ_WRITE",
                                "source": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a/disks/test-instance-group-1",
                                "deviceName": "instance-template-1",
                                "index": 0,
                                "boot": true,
                                "autoDelete": true,
                                "licenses": [
                                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                                ],
                                "interface": "SCSI",
                                "guestOsFeatures": [
                                    {
                                        "type": "VIRTIO_SCSI_MULTIQUEUE"
                                    }
                                ],
                                "kind": "compute#attachedDisk"
                            }
                        ],
                        "metadata": {
                            "fingerprint": "tTiVNsTTlTk=",
                            "items": [
                                {
                                    "key": "instance-template",
                                    "value": "projects/067891234876/global/instanceTemplates/instance-template-1"
                                },
                                {
                                    "key": "created-by",
                                    "value": "projects/067891234876/regions/us-central1/instanceGroupManagers/gio-instance-group-1"
                                }
                            ],
                            "kind": "compute#metadata"
                        },
                        "serviceAccounts": [
                            {
                                "email": "067891234876-compute@developer.gserviceaccount.com",
                                "scopes": [
                                    "https://www.googleapis.com/auth/devstorage.read_only",
                                    "https://www.googleapis.com/auth/logging.write",
                                    "https://www.googleapis.com/auth/monitoring.write",
                                    "https://www.googleapis.com/auth/servicecontrol",
                                    "https://www.googleapis.com/auth/service.management.readonly",
                                    "https://www.googleapis.com/auth/trace.append"
                                ]
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-c/instances/test-instance-group-1",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": true,
                            "preemptible": false
                        },
                        "cpuPlatform": "Intel Haswell",
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "reservationAffinity": {
                            "consumeReservationType": "ANY_RESERVATION"
                        },
                        "displayDevice": {
                            "enableDisplay": false
                        },
                        "kind": "compute#instance"
                    }
                ],
                [],
                {
                    "regions/us-central1": {
                        "instanceGroups": [
                            {
                                "id": "8095311003411251272",
                                "creationTimestamp": "2020-01-02T11:04:07.946-08:00",
                                "name": "test-instance-group-1",
                                "description": "This instance group is controlled by Regional Instance Group Manager 'gio-instance-group-1'. To modify instances in this group, use the Regional Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                "network": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/global/networks/default",
                                "fingerprint": "42WmSpB8rSM=",
                                "selfLink": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/instanceGroups/gio-instance-group-1",
                                "size": 1,
                                "region": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1",
                                "subnetwork": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/subnetworks/default",
                                "kind": "compute#instanceGroup"
                            }
                        ]
                    },
                    "regions/europe-west1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west1"
                                }
                            ]
                        }
                    },
                    "regions/us-west1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-west1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-west1"
                                }
                            ]
                        }
                    },
                    "regions/asia-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-east1"
                                }
                            ]
                        }
                    },
                    "regions/us-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-east1"
                                }
                            ]
                        }
                    },
                    "regions/asia-northeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-northeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-northeast1"
                                }
                            ]
                        }
                    },
                    "regions/asia-southeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-southeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-southeast1"
                                }
                            ]
                        }
                    },
                    "regions/us-east4": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-east4' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-east4"
                                }
                            ]
                        }
                    },
                    "regions/australia-southeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/australia-southeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/australia-southeast1"
                                }
                            ]
                        }
                    },
                    "regions/europe-west2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west2"
                                }
                            ]
                        }
                    },
                    "regions/europe-west3": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west3' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west3"
                                }
                            ]
                        }
                    },
                    "regions/southamerica-east1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/southamerica-east1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/southamerica-east1"
                                }
                            ]
                        }
                    },
                    "regions/asia-south1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-south1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-south1"
                                }
                            ]
                        }
                    },
                    "regions/northamerica-northeast1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/northamerica-northeast1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/northamerica-northeast1"
                                }
                            ]
                        }
                    },
                    "regions/europe-west4": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west4' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west4"
                                }
                            ]
                        }
                    },
                    "regions/europe-north1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-north1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-north1"
                                }
                            ]
                        }
                    },
                    "regions/us-west2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-west2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-west2"
                                }
                            ]
                        }
                    },
                    "regions/asia-east2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-east2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-east2"
                                }
                            ]
                        }
                    },
                    "regions/europe-west6": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/europe-west6' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/europe-west6"
                                }
                            ]
                        }
                    },
                    "regions/asia-northeast2": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/asia-northeast2' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/asia-northeast2"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-central1-f": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-central1-f' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-central1-f"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west1-d": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west1-d' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west1-d"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-west1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east1-d": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east1-d' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east1-d"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-southeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-southeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-southeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-a"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-b"
                                }
                            ]
                        }
                    },
                    "zones/us-east4-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-east4-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-east4-c"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/australia-southeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/australia-southeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/australia-southeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west2-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west3-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west3-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west3-b"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-a"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-b"
                                }
                            ]
                        }
                    },
                    "zones/southamerica-east1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/southamerica-east1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/southamerica-east1-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-south1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-south1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-south1-c"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-a"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-b"
                                }
                            ]
                        }
                    },
                    "zones/northamerica-northeast1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/northamerica-northeast1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/northamerica-northeast1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west4-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west4-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west4-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-north1-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-north1-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-north1-a"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-c"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-b"
                                }
                            ]
                        }
                    },
                    "zones/us-west2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/us-west2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/us-west2-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-east2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-east2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-east2-a"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-b"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-c"
                                }
                            ]
                        }
                    },
                    "zones/europe-west6-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/europe-west6-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/europe-west6-a"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-b": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-b' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-b"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-c": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-c' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-c"
                                }
                            ]
                        }
                    },
                    "zones/asia-northeast2-a": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'zones/asia-northeast2-a' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "zones/asia-northeast2-a"
                                }
                            ]
                        }
                    }
                },
                null,
                null

            );

            plugin.run(cache, {}, callback);
        })

    })
})