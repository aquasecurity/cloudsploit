var expect = require('chai').expect;
var plugin = require('./defaultVPCExists');

const createCache = (err, data) => {
    return {
        networks: {
            list: {
                'global': {
                    err: err,
                    data: data
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

describe('defaultVPCExists', function () {
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
        it('should give failing result if default network exists in the project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default VPC Network exists in the project');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        id: "123456",
                        creationTimestamp: "2021-02-16T22:03:12.817-08:00",
                        name: "default",
                        description: "App VPC",
                        selfLink: "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/app-vpc",
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
        it('should give passing result if default network does not exist in the project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default VPC Network does not exist in the project');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
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
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});