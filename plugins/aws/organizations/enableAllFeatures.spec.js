var expect = require('chai').expect;
var enableAllFeatures = require('./enableAllFeatures')

const createCache = (organization) => {
    return {
        organizations: {
            describeOrganization: {
                'us-east-1': {
                    data: organization,
                },
            },
        },
    };
};

const createErrorCache = (code) => {
    return {
        organizations: {
            describeOrganization: {
                'us-east-1': {
                    err: {
                        code,
                    },
                },
            },
        },
    };
};

describe('enableAllFeatures', function () {
    describe('run', function () {
        it('should FAIL when not all features enabled', function (done) {
            const cache = createCache({
                Arn: 'arn:aws:organizations::111111111111:organization/o-exampleorgid',
                AvailablePolicyTypes: [],
                FeatureSet: 'CONSOLIDATED_BILLING',
                Id: 'o-exampleorgid',
                MasterAccountArn: 'arn:aws:organizations::111111111111:account/o-exampleorgid/111111111111',
                MasterAccountEmail: 'bill@example.com'
            });

            enableAllFeatures.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS when all features enabled', function (done) {
            const cache = createCache({
                Arn: 'arn:aws:organizations::111111111111:organization/o-exampleorgid',
                AvailablePolicyTypes: [{
                    Type: 'SERVICE_CONTROL_POLICY',
                    Status: 'ENABLED',
                }],
                FeatureSet: 'ALL',
                Id: 'o-exampleorgid',
                MasterAccountArn: 'arn:aws:organizations::111111111111:account/o-exampleorgid/111111111111',
                MasterAccountEmail: 'bill@example.com'
            });

            enableAllFeatures.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });
        it('should not add results when not part of organization', function (done) {
            const cache = createErrorCache('AWSOrganizationsNotInUseException')

            enableAllFeatures.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0, 'too many results');
                done();
            });
        });

        it('should UNKNOWN if there was an unexpected error describing organization', function (done) {
            const cache = createErrorCache('ClientError')

            enableAllFeatures.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });
    });
});
