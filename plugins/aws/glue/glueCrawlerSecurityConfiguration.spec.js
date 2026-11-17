var expect = require('chai').expect;
var plugin = require('./glueCrawlerSecurityConfiguration');

const region = 'eu-west-1';
const createCache = (getCrawlers) => ({
    sts: { getCallerIdentity: { 'us-east-1': { data: '123456789012' } } },
    glue: { getCrawlers: { [region]: getCrawlers } }
});
const run = (cache, settings) => {
    let output;
    plugin.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};

describe('glueCrawlerSecurityConfiguration', function () {
    it('should PASS when the crawler has a security configuration', function () {
        const results = run(createCache({ data: [{ Name: 'c1', CrawlerSecurityConfiguration: 'any' }] }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:aws:glue:eu-west-1:123456789012:crawler/c1');
    });

    it('should FAIL when the crawler has no security configuration', function () {
        const results = run(createCache({ data: [{ Name: 'c1' }] }));

        expect(results[0].status).to.equal(2);
    });

    it('should PASS when the configuration matches the required name', function () {
        const results = run(createCache({ data: [{ Name: 'c1', CrawlerSecurityConfiguration: 'tkp-security-configuration' }] }),
            { glue_crawler_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(0);
    });

    it('should FAIL when the configuration differs from the required name', function () {
        const results = run(createCache({ data: [{ Name: 'c1', CrawlerSecurityConfiguration: 'other' }] }),
            { glue_crawler_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('instead of');
    });

    it('should PASS when there are no crawlers', function () {
        const results = run(createCache({ data: [] }));

        expect(results[0].status).to.equal(0);
    });

    it('should return UNKNOWN when crawlers cannot be listed', function () {
        const results = run(createCache({ err: { message: 'AccessDenied' } }));

        expect(results[0].status).to.equal(3);
    });
});
