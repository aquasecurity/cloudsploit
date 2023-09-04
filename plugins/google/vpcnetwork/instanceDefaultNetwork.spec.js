var expect = require('chai').expect;
var plugin = require('./instanceDefaultNetwork');

const createCache = (err, data, instanceErr, instanceData) => {
    return {
        networks: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        compute: {
            list: {
                'us-central1-a': {
                    err: instanceErr,
                    data: instanceData
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'testproject'
                }
            }
        }
    }
};
const instances = [
    {
        "kind": "compute#instance",
        "id": "3111111111",
        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
        "name": "instance-3",
        "description": "",
        "tags": {
            "fingerprint": "42WmSpB8rSM="
        },
        "machineType": "https://www.googleapis.com/compute/v1/projects/testproject/zones/us-central1-a/machineTypes/n1-standard-1",
        "status": "RUNNING",
        "zone": "https://www.googleapis.com/compute/v1/projects/testproject/zones/us-central1-a",
        "canIpForward": true,
        "networkInterfaces": [
            {
                "kind": "compute#networkInterface",
                "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                "subnetwork": "https://www.googleapis.com/compute/v1/projects/testproject/regions/us-central1/subnetworks/default",
                "networkIP": "10.128.0.5",
                "name": "nic0",
                "accessConfigs": [
                    {
                        "kind": "compute#accessConfig",
                        "type": "ONE_TO_ONE_NAT",
                        "name": "External NAT",
                        "natIP": "35.193.110.217",
                        "networkTier": "PREMIUM"
                    }
                ],
                "fingerprint": "Wq0vYR9v5BQ="
            }
        ]
    },
    {
        "kind": "compute#instance",
        "id": "3111111111",
        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
        "name": "instance-2",
        "description": "",
        "tags": {
            "fingerprint": "42WmSpB8rSM="
        },
        "machineType": "https://www.googleapis.com/compute/v1/projects/testproject/zones/us-central1-a/machineTypes/n1-standard-1",
        "status": "RUNNING",
        "zone": "https://www.googleapis.com/compute/v1/projects/testproject/zones/us-central1-a",
        "canIpForward": true,
        "networkInterfaces": [
            {
                "kind": "compute#networkInterface",
                "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/app-vpc",
                "subnetwork": "https://www.googleapis.com/compute/v1/projects/testproject/regions/us-central1/subnetworks/default",
                "networkIP": "10.128.0.5",
                "name": "nic0",
                "accessConfigs": [
                    {
                        "kind": "compute#accessConfig",
                        "type": "ONE_TO_ONE_NAT",
                        "name": "External NAT",
                        "natIP": "35.193.110.217",
                        "networkTier": "PREMIUM"
                    }
                ],
                "fingerprint": "Wq0vYR9v5BQ="
            }
        ]
    }
]
const networks = [
    {
        id: "123456",
        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
        name: "default",
        description: "App VPC",
        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
        subnetworks: [
          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet",
        ],
        routingConfig: {
          routingMode: "GLOBAL",
        },
        mtu: 1460,
        kind: "compute#network",
    },
    {
        id: "123456",
        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
        name: "app-vpc",
        description: "App VPC",
        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/app-vpc",
        autoCreateSubnetworks: false,
        subnetworks: [
          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet",
          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/oregon-subnet1",
        ],
        routingConfig: {
          routingMode: "GLOBAL",
        },
        mtu: 1460,
        kind: "compute#network",
    }
]

describe('instanceDefaultNetwork', function () {
    describe('run', function () {
        it('should give unknown result if a network error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query VPC networks');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no network records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No VPC networks found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if default network does not exist in the project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default Network does not exist in the project');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [networks[1]],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query compute instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
    
            const cache = createCache(
                null,
                networks,
                ['error'],
                []
            );
    
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if default network does not have VM instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default Network does not have any VM instances');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                networks,
                null,
                [instances[1]]
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if default network has VM instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default Network has');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                networks,
                null,
                instances
            );
            plugin.run(cache, {}, callback);
        });

    })
});