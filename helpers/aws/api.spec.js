var expect = require('chai').expect;
var api = require('./api.js');

describe('AWS api definitions', function () {
    it('should reference the lowercase collection key in every reliesOnService', function () {
        // The collector stores results under the lowercase service name (collection.efs, collection.ecr, ...)
        // and looks up reliesOnService as-is, so a value like 'EFS' makes the follow up call silently skip all regions.
        const invalid = [];

        api.postcalls.forEach(function (postcallObj) {
            Object.keys(postcallObj).forEach(function (service) {
                const calls = postcallObj[service];
                Object.keys(calls).forEach(function (callKey) {
                    const reliesOnService = calls[callKey] && calls[callKey].reliesOnService;
                    if (reliesOnService && reliesOnService !== reliesOnService.toLowerCase()) {
                        invalid.push(`${service}:${callKey} reliesOnService '${reliesOnService}'`);
                    }
                });
            });
        });

        expect(invalid, invalid.join(', ')).to.deep.equal([]);
    });
});
