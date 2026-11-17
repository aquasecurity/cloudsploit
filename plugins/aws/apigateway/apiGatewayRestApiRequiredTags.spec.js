var expect = require('chai').expect;
var plugin = require('./apiGatewayRestApiRequiredTags');

const region = 'eu-west-1';
const settings = { required_tags: '{"Owner":"*","Environment":"dev,prod"}' };
const run = (cache, extra) => {
    let output;
    plugin.run(cache, Object.assign({}, settings, extra || {}), (err, results) => { output = results; });
    return output;
};
const goodTags = { 'Owner': 'me', 'Environment': 'dev' };
const createCache = (data) => ({ apigateway: { getRestApis: { [region]: data } } });
const withTags = (tags) => createCache({ data: [Object.assign({}, { id: 'abc123' }, { tags: tags })] });

describe('apiGatewayRestApiRequiredTags', function () {
    it('should PASS when all required tags are present', function () {
        const results = run(withTags(goodTags));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:aws:apigateway:eu-west-1::/restapis/abc123');
    });

    it('should FAIL when a required tag is missing', function () {
        const results = run(withTags({ 'Environment': 'dev' }));

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Owner');
    });

    it('should FAIL when a tag has a value that is not allowed', function () {
        const results = run(withTags({ 'Owner': 'me', 'Environment': 'acc' }));

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Environment');
    });

    it('should FAIL when there are no tags', function () {
        expect(run(withTags({  }))[0].status).to.equal(2);
        expect(run(createCache({ data: [{ id: 'abc123' }] }))[0].status).to.equal(2);
    });

    it('should not evaluate resources with an exempt tag key', function () {
        const results = run(withTags({ 'managed-by-x': '1' }), { required_tags_exempt_keys: 'x, managed-by-x' });

        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('exempt');
    });

    it('should PASS when no required tags are configured', function () {
        expect(run(withTags({  }), { required_tags: '{}' })[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the setting is not valid JSON', function () {
        expect(run(withTags(goodTags), { required_tags: 'nope' })[0].status).to.equal(3);
    });

    it('should PASS when there are none', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when they cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
