var expect = require('chai').expect;
var securityLakeVpcFlowLogsEnabled = require('./securityLakeVpcFlowLogsEnabled');

const accountId = '123456789012';
const region = 'eu-west-1';
const dataLakeArn = 'arn:aws:securitylake:eu-west-1:123456789012:data-lake/default';

const dataLake = (overrides) => Object.assign({ dataLakeArn, region, createStatus: 'COMPLETED' }, overrides);
const awsSource = (sourceName) => ({ awsLogSource: { sourceName, sourceVersion: '2.0' } });

const createCache = (dataLakes, logSources) => {
    const cache = {
        sts: { getCallerIdentity: { 'us-east-1': { data: accountId } } },
        securitylake: {
            listDataLakes: { [region]: dataLakes },
            listLogSources: { [region]: logSources }
        }
    };
    return cache;
};

describe('securityLakeVpcFlowLogsEnabled', function () {
    describe('run', function () {
        it('should PASS when VPC Flow Logs is a source in the data lake', function (done) {
            const cache = createCache(
                { data: [dataLake()] },
                { data: [{ account: accountId, region, sources: [awsSource('CLOUD_TRAIL_MGMT'), awsSource('VPC_FLOW')] }] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal(region);
                expect(results[0].resource).to.equal(dataLakeArn);
                expect(results[0].message).to.include('VPC Flow Logs is enabled');
                done();
            });
        });

        it('should FAIL when the data lake has other sources but not VPC Flow Logs', function (done) {
            const cache = createCache(
                { data: [dataLake()] },
                { data: [{ account: accountId, region, sources: [awsSource('ROUTE53'), awsSource('CLOUD_TRAIL_MGMT')] }] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].resource).to.equal(dataLakeArn);
                expect(results[0].message).to.include('VPC Flow Logs is not enabled');
                done();
            });
        });

        it('should FAIL when the data lake has no log sources at all', function (done) {
            const cache = createCache({ data: [dataLake()] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL when only another account has VPC Flow Logs enabled', function (done) {
            const cache = createCache(
                { data: [dataLake()] },
                { data: [{ account: '999999999999', region, sources: [awsSource('VPC_FLOW')] }] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should ignore custom log sources named like the AWS source', function (done) {
            const cache = createCache(
                { data: [dataLake()] },
                { data: [{ account: accountId, region, sources: [{ customLogSource: { sourceName: 'VPC_FLOW' } }] }] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS when Security Lake is not enabled and it is not required', function (done) {
            const cache = createCache({ data: [] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security Lake is not enabled');
                done();
            });
        });

        it('should FAIL when Security Lake is not enabled and it is required', function (done) {
            const cache = createCache({ data: [] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, { security_lake_required: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('Security Lake is not enabled');
                done();
            });
        });

        it('should not use a data lake from another region', function (done) {
            const cache = createCache({ data: [dataLake({ region: 'us-east-1' })] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('not enabled in the region');
                done();
            });
        });

        it('should FAIL when the data lake could not be created', function (done) {
            const cache = createCache({ data: [dataLake({ createStatus: 'FAILED' })] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('creation failed');
                done();
            });
        });

        it('should WARN when the data lake is still being created', function (done) {
            const cache = createCache({ data: [dataLake({ createStatus: 'PENDING' })] }, { data: [] });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('PENDING');
                done();
            });
        });

        it('should return UNKNOWN when the data lakes cannot be listed', function (done) {
            const cache = createCache({ err: { message: 'AccessDeniedException' } }, {});

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Security Lake data lakes');
                done();
            });
        });

        it('should return UNKNOWN when the log sources cannot be listed', function (done) {
            const cache = createCache({ data: [dataLake()] }, { err: { message: 'AccessDeniedException' } });

            securityLakeVpcFlowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Security Lake log sources');
                expect(results[0].resource).to.equal(dataLakeArn);
                done();
            });
        });

        it('should not return results when nothing was collected for the region', function (done) {
            securityLakeVpcFlowLogsEnabled.run({ securitylake: { listDataLakes: {} } }, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
