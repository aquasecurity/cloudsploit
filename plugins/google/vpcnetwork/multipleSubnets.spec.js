var expect = require('chai').expect;
var plugin = require('./multipleSubnets');

const createCache = (err, data) => {
    return {
        networks: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('multipleSubnets', function () {
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
        it('should give failing result if only one subnet is used in provided regions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Only one subnet in these regions is used');
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
        it('should give passing result if more than one subnet is used in provided regions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('different subnets used in these regions');
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
        it('should give failing result if only the default subnet is used in provided regions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Only the default subnet in these regions is used');
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
                          "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-east1/subnetworks/default",
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
        it('should give passing result if the VPC does not have any subnets in provided regions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The VPC does not have any subnets in these regions');
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