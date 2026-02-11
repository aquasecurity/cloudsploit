var expect = require('chai').expect;
var plugin = require('./cloudFunctionV2VPCConnector');


const functions = [
    {
        "name": "projects/my-test-project/locations/us-central1/services/function-1",
        "labels": {
            "goog-managed-by": "cloudfunctions",
            "goog-cloudfunctions-runtime": "nodejs20"
        },
        "template": {
            "serviceAccount": "test@test-project.iam.gserviceaccount.com"
        },
        "ingress": "INGRESS_TRAFFIC_ALL",
        "buildConfig": {
            "functionTarget": "helloHttp"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/services/function-2",
        "labels": {
            "goog-managed-by": "cloudfunctions",
            "goog-cloudfunctions-runtime": "nodejs20"
        },
        "template": {
            "serviceAccount": "test@test-project.iam.gserviceaccount.com",
            "vpcAccess": {
                "connector": "projects/my-test-project/locations/us-central1/connectors/cloud-func-connector",
                "egress": "ALL_TRAFFIC"
            }
        },
        "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
        "buildConfig": {
            "functionTarget": "helloHttp"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/services/function-3",
        "labels": {
            "goog-managed-by": "cloudfunctions",
            "goog-cloudfunctions-runtime": "nodejs20"
        },
        "template": {
            "serviceAccount": "test@test-project.iam.gserviceaccount.com",
            "vpcAccess": {
                "networkInterfaces": [
                    {
                        "network": "testvpc",
                        "subnetwork": "testvpc"
                    }
                ],
                "egress": "PRIVATE_RANGES_ONLY"
            }
        },
        "buildConfig": {
            "functionTarget": "helloHttp"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/services/regular-service",
        "labels": {
            "app": "my-app"
        },
        "template": {
            "vpcAccess": {
                "connector": "projects/my-test-project/locations/us-central1/connectors/cloud-func-connector"
            }
        }
    }
];

const createCache = (list, err) => {
    return {
        functionsv2: {
            list: {
                'us-central1': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('serverlessVPCAccess', function () {
    describe('run', function () {
        it('should give passing result if no Cloud Functions V2 found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Google Cloud functions found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Google Cloud functions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Google Cloud functions');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Cloud Function is using a VPC Connector to route all traffic', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud Function is using a VPC Connector to route all traffic');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [functions[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Cloud Function is using a VPC Connector for requests to private IPs only', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud Function is using a VPC Connector for requests to private IPs only');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[2]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Cloud Function is not configured with Serverless VPC Access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud Function is not configured with Serverless VPC Access');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should not check non-Cloud Functions services in Cloud Run API response', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(0);
                done();
            };

            const cache = createCache(
                [functions[3]],
                null
            );

            plugin.run(cache, {}, callback);
        });

    })
});
