const expect = require('chai').expect;
var enableAccessLogging = require('./enableAccessLogging');


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
        "virtualGatewayName": "number2"
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
                    err: listMeshesErr,
                    data: listMeshes
                }
            },
            listVirtualGateways: {
                'us-east-1': {
                    [name]: {
                        err: listVirtualGatewaysErr,
                        data: {
                            "virtualGateways":listVirtualGateways
                        }     
                    }
                }
            },
            describeVirtualGateway: {
                'us-east-1': {
                    [gatewayName]: {
                        err: describeVirtualGatewayErr,
                        data: describeVirtualGateway
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

describe('enableAccessLogging', function () {
    describe('run', function () {

        it('should PASS if access logging is enabled and configured for Amazon App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], [listVirtualGateways[1]], describeVirtualGateway[1]);
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Mesh virtual gateway has access logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if access logging is not enabled for Amazon App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], [listVirtualGateways[0]], describeVirtualGateway[0]);
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('access logging is not enabled for Amazon App Mesh virtual gateways');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No App Meshes found', function (done) {
            const cache = createCache([]);
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No App Meshes found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for App Meshes', function (done) {
            const cache = createCache(null, null, null, { message: 'Unable to query for App Meshes'});
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query for AppMesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], {}, describeVirtualGateway[0], { message: 'Unable to query for AppMesh virtual gateways'});
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list App Meshes response not found', function (done) {
            const cache = createNullCache();
            enableAccessLogging.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});