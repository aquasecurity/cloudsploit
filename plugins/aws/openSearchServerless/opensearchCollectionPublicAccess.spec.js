const expect = require('chai').expect;
var collectionPublicAccess = require('./opensearchCollectionPublicAccess');

const listCollections = [
    {
       "arn": 'arn:aws:lambda:us-east-1:000011112222:function:testing-123',
       "id": "123xyz",
       "name": "test",
       "status": "ACTIVE"
    },
];
const listSecurityPolicies =[
    {
        "name": "auto-test",
        "type": "network",
    }
]

const getSecurityPolicy = [
    
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: [ { Rules: [{ Resource:["collection/test"], ResourceType:'collection' }], AllowFromPublic: true } ],
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'network'
        }
    },
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: [ { Rules: [{ Resource:["collection/temp"], ResourceType:'collection' }], AllowFromPublic: true } ],
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'network'
        }
    }
]

const createCache = (listCollections, listSecurityPolicies, getSecurityPolicy) => {
    return {
        opensearchserverless: {
            listCollections: {
                'us-east-1': {
                    data: listCollections
                }
            },
            listNetworkSecurityPolicies: {
                'us-east-1': {
                    data: listSecurityPolicies               
                }
            },
            getNetworkSecurityPolicy: {
                'us-east-1': {
                    "auto-test":{
                        data: getSecurityPolicy
                    }
                }
            }
        }
    };
};

describe('collectionPublicAccess', function () {
    describe('run', function () {

        it('should give Unknown result if unable to list collections', function (done) {
            const cache = createCache(null);
            collectionPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query list OpenSearch collections:');
                done();
            });
        });

        it('should Pass if no collection found', function (done) {
            const cache = createCache([]);
            collectionPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OpenSearch collections found');
                done();
            });
        });

        it('should give UNKNOWN result if unable to list security Policies', function (done) {
            const cache = createCache(listCollections, null);
            collectionPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list OpenSearch security policies:');
                done();
            });
        });

        it('should PASS if collection is publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[0]);
            collectionPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenSearch collection is publicly accessible');
                done();
            });
        });

        it('should FAIL if collection is not publicly accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[1]);
            collectionPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenSearch collection is not publicly accessible');
                done();
            });
        });

    });
});