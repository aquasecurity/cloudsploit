var expect = require('chai').expect;
var restrictExternalTraffic = require('./restrictExternalTraffic');

const listMeshes = [   
    {
        "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1",
        "createdAt": "2022-01-12T15:33:12.228000+05:00",
        "lastUpdatedAt": "2022-01-12T15:33:12.228000+05:00",
        "meshName": "mine1",
        "meshOwner": "000011112222",
        "resourceOwner": "000011112222",
        "version": 1
    }
];

const describeMesh = [
    {
        "mesh": {
            "meshName": "mine1",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1",
                "createdAt": "2022-01-12T15:33:12.228000+05:00",
                "lastUpdatedAt": "2022-01-12T15:33:12.228000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "e9812fab-3e03-49a5-aad8-4a0b54d873da",
                "version": 1
            },
            "spec": {
                "egressFilter": {
                    "type": "ALLOW_ALL"
                }
            },
            "status": {
                "status": "ACTIVE"
            }
        }
    },
    {
        "mesh": {
            "meshName": "mine1",
            "metadata": {
                "arn": "arn:aws:appmesh:us-east-1:000011112222:mesh/mine1",
                "createdAt": "2022-01-12T15:33:12.228000+05:00",
                "lastUpdatedAt": "2022-01-12T15:33:12.228000+05:00",
                "meshOwner": "000011112222",
                "resourceOwner": "000011112222",
                "uid": "e9812fab-3e03-49a5-aad8-4a0b54d873da",
                "version": 1
            },
            "spec": {
                "egressFilter": {
                    "type": "DROP_ALL"
                }
            },
            "status": {
                "status": "ACTIVE"
            }
        }
    }
];


const createCache = (mesh, describeMesh, meshErr, describeMeshErr) => {
    var name = (mesh && mesh.length) ? mesh[0].meshName: null;
    return {
        appmesh: {
            listMeshes: {
                'us-east-1': {
                    err: meshErr,
                    data: mesh
                },
            },
            describeMesh: {
                'us-east-1': {
                    [name]: {
                        data: describeMesh,
                        err: describeMeshErr
                    }
                }
            }
        },
    };
};

describe('restrictExternalTraffic', function () {
    describe('run', function () {
        it('should PASS if App Mesh mesh does not allow access to external services', function (done) {
            const cache = createCache([listMeshes[0]], describeMesh[1]);
            restrictExternalTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Mesh mesh does not allow access to external services');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if App Mesh mesh allows access to external services', function (done) {
            const cache = createCache([listMeshes[0]], describeMesh[0]);
            restrictExternalTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Mesh mesh allows access to external services');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no App Meshes found', function (done) {
            const cache = createCache([]);
            restrictExternalTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No App Mesh meshes found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should UNKNOWN if Unable to query for App Mesh meshes', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for App Mesh meshes" });
            restrictExternalTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for App Mesh meshes');
                done();
            });
        });

        it('should UNKNOWN if Unable to describe App Mesh mesh', function (done) {
            const cache = createCache([listMeshes[0]], null, null, { message: "Unable to describe App Mesh mesh" });
            restrictExternalTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to describe App Mesh mesh');
                done();
            });
        });
    });
})
