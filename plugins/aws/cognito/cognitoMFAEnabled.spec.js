var expect = require('chai').expect;
var cognitoMFAEnabled = require('./cognitoMFAEnabled');

const listUserPools = [
    {
    Id: 'us-east-1_cbDh8sCFGH',
    Name: 'test',
    LambdaConfig: {}
    }
];
const describeUserPool = [
    {
      Id: 'us-east-1_cbDh8sCFGH',
      Name: 'test',
      LambdaConfig: {},
      MfaConfiguration: 'OFF',
      EstimatedNumberOfUsers: 0,
      UserPoolTags: {},
      Arn: 'arn:aws:cognito-idp:us-east-1:1111222222222:userpool/us-east-1_cbDh8sCFGH',
    },
    {
      Id: 'us-east-1_cbDh8sCFGH',
      Name: 'test',
      LambdaConfig: {},
      MfaConfiguration: 'ON',
      EstimatedNumberOfUsers: 0,
      UserPoolTags: {},
      Arn: 'arn:aws:cognito-idp:us-east-1:1111222222222:userpool/us-east-1_cbDh8sCFGH',
    }
]

const createCache = (poolList, describe) => {
    return {
        cognitoidentityserviceprovider: {
            listUserPools: {
                'us-east-1': {
                    err: null,
                    data: poolList
                }
            },
            describeUserPool: {
                'us-east-1':{
                    'us-east-1_cbDh8sCFGH':{
                    err: null,
                    data: { UserPool: describe }
                }
                }
            }
        },
        
    }
};

describe('cognitoMFAEnabled', function () {
    describe('run', function () {
        it('should give unknown result if unable to list user pools', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query Cognito user pools:');
                done()
            };

            const cache = createCache(null, []);
            cognitoMFAEnabled.run(cache, {}, callback);
        });

        it('should give passing result if User pool not found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Cognito user pools found');
                done();
            };
            const cache = createCache([], null);
            cognitoMFAEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query describe user pool api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to describe Cognito user pool');
                done();
            };

            const cache = createCache([listUserPools[0]], null);
            cognitoMFAEnabled.run(cache, {}, callback);
        });

        it('should give passing result if User pool has MFA enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('User pool has MFA enabled');
                done();
            };

            const cache = createCache([listUserPools[0]], describeUserPool[1]);
            cognitoMFAEnabled.run(cache, {}, callback);
        });

        it('should give failing result if User pool does not have MFA enabled', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].region).to.equal('us-east-1');
                    expect(results[0].message).to.include('User pool does not have MFA enabled');
                    done();
                };

            const cache = createCache([listUserPools[0]], describeUserPool[0]);
            cognitoMFAEnabled.run(cache, {}, callback);
        });

    });
});