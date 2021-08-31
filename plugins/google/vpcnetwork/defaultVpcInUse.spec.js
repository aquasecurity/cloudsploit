var expect = require('chai').expect;
var plugin = require('./defaultVpcInUse');

const createCache = (err, data) => {
    instances = []
    if(data && data.length){
        instances = data[0].instances
    }
    return {
        networks: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        instances: {
            compute:{
                list: {
                    'us-central1-a':{
                        err: err,
                        data: instances
                    }
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'testProj'
                }
            }
        }
    }
};

describe('defaultVpcInUse', function () {
    describe('run', function () {
        it('should give unknown result if a subnetwork error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query networks');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no subnetwork records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No networks found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no default vpc is found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No default VPC found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "459972978914955087",
                        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
                        name: "app-vpc",
                        description: "App VPC",
                        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/app-vpc",
                        autoCreateSubnetworks: false,
                        subnetworks: [
                          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet",
                        ],
                        routingConfig: {
                          routingMode: "GLOBAL",
                        },
                        mtu: 1460,
                        kind: "compute#network",
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if default vpc is not in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default VPC is not in use');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "459972978914955087",
                        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
                        name: "default",
                        description: "App VPC",
                        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/app-vpc",
                        autoCreateSubnetworks: false,
                        subnetworks: [
                          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet",
                        ],
                        routingConfig: {
                          routingMode: "GLOBAL",
                        },
                        mtu: 1460,
                        kind: "compute#network",
                        instances: [
                            {
                                id: "5266474242833977495",
                                creationTimestamp: "2021-04-09T12:43:53.256-07:00",
                                name: "testing1",
                                description: "",
                                tags: {
                                    fingerprint: "42WmSpB8rSM=",
                                },
                                machineType: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/machineTypes/e2-micro",
                                status: "RUNNING",
                                zone: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a",
                                canIpForward: false,
                                networkInterfaces: [
                                    {
                                    network: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default-vpc",
                                    subnetwork: "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/default-vpc",
                                    networkIP: "10.128.0.2",
                                    name: "nic0",
                                    accessConfigs: [
                                        {
                                        type: "ONE_TO_ONE_NAT",
                                        name: "External NAT",
                                        natIP: "34.67.184.85",
                                        networkTier: "PREMIUM",
                                        kind: "compute#accessConfig",
                                        },
                                    ],
                                    fingerprint: "0ooE15ntQvk=",
                                    kind: "compute#networkInterface",
                                    },
                                ],
                            }
                        ]
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if default vpc is in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default VPC is in use');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "459972978914955087",
                        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
                        name: "default",
                        description: "App VPC",
                        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                        autoCreateSubnetworks: false,
                        subnetworks: [
                          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet",
                        ],
                        routingConfig: {
                          routingMode: "GLOBAL",
                        },
                        mtu: 1460,
                        kind: "compute#network",
                        instances: [
                            {
                                id: "5266474242833977495",
                                creationTimestamp: "2021-04-09T12:43:53.256-07:00",
                                name: "testing1",
                                description: "",
                                tags: {
                                    fingerprint: "42WmSpB8rSM=",
                                },
                                machineType: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/machineTypes/e2-micro",
                                status: "RUNNING",
                                zone: "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a",
                                canIpForward: false,
                                networkInterfaces: [
                                    {
                                    network: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                                    subnetwork: "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/default-vpc",
                                    networkIP: "10.128.0.2",
                                    name: "nic0",
                                    accessConfigs: [
                                        {
                                        type: "ONE_TO_ONE_NAT",
                                        name: "External NAT",
                                        natIP: "34.67.184.85",
                                        networkTier: "PREMIUM",
                                        kind: "compute#accessConfig",
                                        },
                                    ],
                                    fingerprint: "0ooE15ntQvk=",
                                    kind: "compute#networkInterface",
                                    },
                                ],
                            }
                        ]
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});