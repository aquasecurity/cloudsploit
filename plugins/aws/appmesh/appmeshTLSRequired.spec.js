const expect = require('chai').expect;
var appmeshTLSRequired = require('./appmeshTLSRequired');


const listMeshes = [
    { 
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh1",
        "createdAt": "2022-02-24T16:52:04.455000+05:00",
        "lastUpdatedAt": "2022-02-24T16:52:04.455000+05:00",
        "meshName": 'sadeed-mesh1',
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "uid": "d6e1ce9d-049d-42ec-9be5-3b8451b6c384",
        "version": 1
    },
    { 
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh2",
        "createdAt": "2022-02-24T16:52:04.455000+05:00",
        "lastUpdatedAt": "2022-02-24T16:52:04.455000+05:00",
        "meshName": 'sadeed-mesh2',
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "uid": "d6e1ce9d-049d-42ec-9be5-3b8451b6c384",
        "version": 1
    },
];

const listVirtualGateways = [   
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh1/virtualGateway/mine-vg-1",
        "createdAt": "2022-02-24T16:59:37.097000+05:00",
        "lastUpdatedAt": "2022-02-24T16:59:37.097000+05:00",
        "meshName": "sadeed-mesh1",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1,
        "virtualGatewayName": "mine-vg-1"
            
    },
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh2/virtualGateway/mine-vg-2",
        "createdAt": "2022-02-24T16:59:37.097000+05:00",
        "lastUpdatedAt": "2022-02-24T16:59:37.097000+05:00",
        "meshName": "sadeed-mesh2",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1,
        "virtualGatewayName": "mine-vg-2"     
    }
];

const describeVirtualGateway = [
    {
        "virtualGateway": {
            "meshName": "sadeed-mesh1",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh1/virtualGateway/mine-vg-1",
                "createdAt": "2022-02-24T16:59:37.097000+05:00",
                "lastUpdatedAt": "2022-02-24T16:59:37.097000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "16759e86-7eff-428e-87bb-782598002446",
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
                        },
                        "tls": {
                            "certificate": {
                                "sds": {
                                    "secretName": "mine1"
                                }
                            },
                            "mode": "STRICT"
                        }
                    }
                ],
                "logging": {}
            },
            "status": {
                "status": "ACTIVE"
            },
            "virtualGatewayName": "mine-vg-1"
        }
    },
    {
        "virtualGateway": {
            "meshName": "sadeed-mesh2",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh2/virtualGateway/mine-vg-2",
                "createdAt": "2022-02-24T16:59:37.097000+05:00",
                "lastUpdatedAt": "2022-02-24T16:59:37.097000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "16759e86-7eff-428e-87bb-782598002446",
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
                        },
                        "tls": {
                            "certificate": {
                                "sds": {
                                    "secretName": "mine1"
                                }
                            },
                            "mode": "DISABLED"
                        }
                    }
                ],
                "logging": {}
            },
            "status": {
                "status": "ACTIVE"
            },
            "virtualGatewayName": "mine-vg-2"
        }
    },
];


const createCache = (listMeshes, listVirtualGateways,  describeVirtualGateway, listMeshesErr, listVirtualGatewaysErr, describeVirtualGatewayErr) => {
    var name = (listMeshes && listMeshes.length) ? listMeshes[0].meshName : null;
    var gatewayName = (listVirtualGateways && listVirtualGateways.length) ? listVirtualGateways[0].virtualGatewayName : null;
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
                            "virtualGateways": listVirtualGateways
                            
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

describe('appmeshTLSRequired', function () {
    describe('run', function () {
        it('should PASS if App Mesh vitual gateway listeners restrict TLS enabled connections', function (done) {
            const cache = createCache([listMeshes[0]], [listVirtualGateways[0]], describeVirtualGateway[0]);
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('App Mesh virtual gateway listeners restrict TLS enabled connections')
                done();
            });
        });

        it('should FAIL if App Mesh vitual gateway listeners does not restrict TLS enabled connections', function (done) {
            const cache = createCache([listMeshes[1]], [listVirtualGateways[1]], describeVirtualGateway[1]);
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('App Mesh virtual gateway listeners does not restrict TLS enabled connections')
                done();
            });
        });

        it('should PASS if no App Mesh meshes found', function (done) {
            const cache = createCache([]);
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No App Mesh meshes found')
                done();
            });
        });

        it('should UNKNOWN if Unable to list App Mesh meshes', function (done) {
            const cache = createCache(null, null, null, { message: 'Unable to list App Mesh meshes'});
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list App Mesh meshes')
                done();
            });
        });

        it('should UNKNOWN if unable to list App Mesh virtual gateways', function (done) {
            const cache = createCache([listMeshes[0]], [], describeVirtualGateway[0], null, { message: 'Unable to list App Mesh virtual gateways'});
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list App Mesh virtual gateways')
                done();
            });
        });

        it('should not return anything if list App Mesh meshes response not found', function (done) {
            const cache = createNullCache();
            appmeshTLSRequired.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});