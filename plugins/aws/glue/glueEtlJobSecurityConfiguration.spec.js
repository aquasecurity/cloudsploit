var expect = require('chai').expect;
var plugin = require('./glueEtlJobSecurityConfiguration');

const region = 'eu-west-1';
const createCache = (data) => ({
    sts: { getCallerIdentity: { 'us-east-1': { data: '123456789012' } } },
    glue: { getJobs: { [region]: data } }
});
const run = (cache, settings) => {
    let output;
    plugin.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};

describe('glueEtlJobSecurityConfiguration', function () {
    it('should PASS when the ETL job has a security configuration', function () {
        const results = run(createCache({ data: [{ Name: 'x1', SecurityConfiguration: 'any' }] }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:aws:glue:eu-west-1:123456789012:job/x1');
    });

    it('should FAIL when the ETL job has no security configuration', function () {
        const results = run(createCache({ data: [{ Name: 'x1' }] }));

        expect(results[0].status).to.equal(2);
    });

    it('should PASS when the configuration matches the required name', function () {
        const results = run(createCache({ data: [{ Name: 'x1', SecurityConfiguration: 'tkp-security-configuration' }] }),
            { glue_etl_job_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(0);
    });

    it('should FAIL when the configuration differs from the required name', function () {
        const results = run(createCache({ data: [{ Name: 'x1', SecurityConfiguration: 'other' }] }),
            { glue_etl_job_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('instead of');
    });

    it('should PASS when there are none', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when they cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
