const expect = require('chai').expect;
var appmeshVGAccessLogging = require('./appmeshVGAccessLogging');

const listMeshes = [
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1",
        "createdAt": "2022-01-11T18:09:34.022000+05:00",
        "lastUpdatedAt": "2022-01-11T18:09:34.022000+05:00",
        "meshName": "mine1",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1
    }
];

const listVirtualGateways = [  
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1/virtualGateway/number2",
        "createdAt": "2022-01-11T19:45:12.805000+05:00",
        "lastUpdatedAt": "2022-01-11T19:45:12.805000+05:00",
        "meshName": "mine1",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1,
        "virtualGatewayName": "number2",
    },
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1/virtualGateway/number1",
        "createdAt": "2022-01-11T18:11:31.773000+05:00",
        "lastUpdatedAt": "2022-01-11T18:11:31.773000+05:00",
        "meshName": "mine1",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1,
        "virtualGatewayName": "number1"
    }
];

const describeVirtualGateway = [
    {
        "virtualGateway": {
            "meshName": "mine1",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1/virtualGateway/number2",
                "createdAt": "2022-01-11T19:45:12.805000+05:00",
                "lastUpdatedAt": "2022-01-11T19:45:12.805000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "19f47311-04d5-4ef4-b81c-eb931f50509a",
                "version": 1
            },
            "spec": {
                "backendDefaults": {
                    "clientPolicy": {}
                },
                "listeners": [
                    {
                        "portMapping": {
                            "port": 1,
                            "protocol": "http"
                        }
                    }
                ],
                "logging": {}
            },
            "status": {
                "status": "ACTIVE"
            },
            "virtualGatewayName": "number2"
        }
    },
    {
        "virtualGateway": {
            "meshName": "mine1",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1/virtualGateway/number1",
                "createdAt": "2022-01-11T18:11:31.773000+05:00",
                "lastUpdatedAt": "2022-01-11T18:11:31.773000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "3965139e-cc80-44b3-86ca-353ae83b5330",
                "version": 1
            },
            "spec": {
                "backendDefaults": {
                    "clientPolicy": {
                        "tls": {
                            "enforce": false,
                            "ports": [],
                            "validation": {
                                "trust": {
                                    "sds": {
                                        "secretName": "hhjhj"
                                    }
                                }
                            }
                        }
                    }
                },
                "listeners": [
                    {
                        "portMapping": {
                            "port": 1,
                            "protocol": "http"
                        }
                    }
                ],
                "logging": {
                    "accessLog": {
                        "file": {
                            "path": "hhjukh"
                        }
                    }
                }
            },
            "status": {
                "status": "ACTIVE"
            },
            "virtualGatewayName": "number1"
        }
    }
];


const createCache = (listMeshes, listVirtualGateways,  describeVirtualGateway, listMeshesErr, listVirtualGatewaysErr, describeVirtualGatewayErr) => {
    let name = (listMeshes && listMeshes.length) ? listMeshes[0].meshName : null;
    let gatewayName = (listVirtualGateways && listVirtualGateways.length) ? listVirtualGateways[0].virtualGatewayName : null;
    return {
        appmesh: {
            listMeshes: {
                'us-east-1': {
                    data: listMeshes,
                    err: listMeshesErr
                }
            },
            listVirtualGateways: {
                'us-east-1': {
                    [name]: {
                        data: {
                            "virtualGateways":listVirtualGateways
                        },
                        err: listVirtualGatewaysErr,
                    }
                }
            },
            describeVirtualGateway: {
                'us-east-1': {
                    [gatewayName]: {
                        data: describeVirtualGateway,
                        err: describeVirtualGatewayErr
                    }
                }
            },
        },
    };
};

const createNullCache = () => {
    return {
        appmesh: {
            listMeshes: {
                'us-east-1': null
            }
        }
    };
};

describe('appmeshVGAccessLogging', function () {
    describe('run', function () {

        it('should PASS if access logging is enabled and configured for Amazon App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], [listVirtualGateways[1]], describeVirtualGateway[1]);
            appmeshVGAccessLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Mesh virtual gateway has access logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if access logging is not enabled for Amazon App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], [listVirtualGateways[0]], describeVirtualGateway[0]);
            appmeshVGAccessLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Mesh virtual gateway does not have access logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No App Meshes found', function (done) {
            const cache = createCache([]);
            appmeshVGAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No App Mesh meshes found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for App Mesh meshes', function (done) {
            const cache = createCache(null, null, null, { message: 'Unable to query for App Meshes'});
            appmeshVGAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Mesh meshes');
                done();
            });
        });

        it('should UNKNOWN if unable to query for App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], null, describeVirtualGateway[0], null,  { message: 'Unable to query for AppMesh virtual gateways'});
            appmeshVGAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Mesh virtual gateways');
                done();
            });
        });

        it('should not return anything if list App Meshes response not found', function (done) {
            const cache = createNullCache();
            appmeshVGAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});