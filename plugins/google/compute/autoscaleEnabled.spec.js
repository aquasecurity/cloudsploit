var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./autoscaleEnabled');

const createCache = (instanceData, autoscalers, instanceGroupsError, autoScalersError) => {
    return {
        instanceGroups: {
            aggregatedList: {
                'global': {
                    data: instanceData,
                    err: instanceGroupsError
                }
            }
        },
        autoscalers: {
            aggregatedList: {
                'global': {
                    data: autoscalers,
                    err: autoScalersError
                }
            }
        },
        clusters: {
            list: {
                'global': {
                    data: clusters,
                    err: null
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'tets-proj'
                }
            }
        }
    }
};

const instanceGroupData = {
    "zones/us-central1-a": {
        "instanceGroups": [
            {
                "id": "111111",
                "creationTimestamp": "2019-12-17T11:52:28.215-08:00",
                "name": "instance-group-1",
                "description": "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                "network": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/global/networks/default",
                "fingerprint": "42WmSpB8rSM=",
                "zone": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a",
                "selfLink": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/zones/us-central1-a/instanceGroups/instance-group-1",
                "size": 1,
                "subnetwork": "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/subnetworks/default",
                "kind": "compute#instanceGroup"
            }
        ]
    },
};
const clusters = [

    {
        "name": "cluster-1",
        "subnetwork": "default",
        "nodePools": [
            {
                "name": "default-pool",
                "initialNodeCount": 3,
                "autoscaling": {},
                "locations": [
                    "us-central1-c"
                ],
                "selfLink": "https://container.googleapis.com/v1beta1/projects/akhtar-dev-aqua/zones/us-central1-c/clusters/cluster-1/nodePools/default-pool",
                "version": "1.20.10-gke.1600",
                "instanceGroupUrls": [
                    "https://www.googleapis.com/compute/v1/projects/frosty-forest-647198/regions/us-central1/instanceGroups/instance-group-1"
                ],
                "status": "RUNNING",
                "upgradeSettings": {
                    "maxSurge": 1
                }
            }
        ],
        "locations": [
            "us-central1-c"
        ],
    }
]

describe('autoscaleEnabled', function () {
    describe('run', function () {

        it('should give unknown if an instance group error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instance groups');
                done()
            };

            const cache = createCache(
                [], [], ['error'], null
            );

            plugin.run(cache, { minimum_cpu_utilization_target: '60' }, callback);
        });

        it('should pass no instance groups found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instance groups found');
                done()
            };

            const cache = createCache(
                [], [], null, null
            );

            plugin.run(cache, { minimum_cpu_utilization_target: '60' }, callback);
        });



        it('should fail if instance instance group does not have autoscaling enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance group does not have autoscale enabled');
                done()
            };

            const cache = createCache(
                instanceGroupData,
                {
                    "zones/us-central1-a": {
                        "autoscalers":
                            [
                                {
                                    creationTimestamp: '2021-08-16T01:24:57.502-07:00',
                                    name: 'instance-group-2',
                                    autoscalingPolicy: { cpuUtilization: { utilizationTarget: 0.001, predictiveMethod: 'NONE' } },
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    status: 'ACTIVE',
                                    kind: 'compute#autoscaler'
                                }
                            ]
                    }
                },
                null, null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if instance group has autoscaling enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('All instance groups have autoscale enabled');
                done()
            };

            const cache = createCache(
                instanceGroupData,
                {
                    "zones/us-central1-a": {
                        "autoscalers":
                            [
                                {
                                    creationTimestamp: '2021-08-16T01:24:57.502-07:00',
                                    name: 'instance-group-1',
                                    autoscalingPolicy: { cpuUtilization: { utilizationTarget: 0.001, predictiveMethod: 'NONE' } },
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    status: 'ACTIVE',
                                    kind: 'compute#autoscaler'
                                }
                            ]
                    }
                },
                null, null
            );

            plugin.run(cache, {}, callback);
        })
    })
});