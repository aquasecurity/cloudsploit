var expect = require('chai').expect;
var suppress = require('./suppress');

describe('create', function () {
    it('should return undefined when no filter specified', function () {
        var filter = suppress.create([]);
        expect(filter('any')).to.be.undefined;
    });

    it('should return the filter if matches', function () {
        var filter = suppress.create(['*:*:n*']);
        expect(filter('plugin:region:name')).to.equal('*:*:n*');
    });

    it('should return the filter if matches whole word', function () {
        var filter = suppress.create(['*:*:longer']);
        expect(filter('plugin:region:longer')).to.equal('*:*:longer');
    });

    it('should return the filter if multiple and second matches', function () {
        var filter = suppress.create([
            '*:*:first*',
            'plugin:region:second'
        ]);
        expect(filter('plugin:region:second')).to.equal('plugin:region:second');
    });

    describe('validation', function() {
        it('should accept valid suppression patterns', function() {
            const validPatterns = [
                'acmValidation:us-east-1:*',
                'plugin_name:*:resource-123',
                'test_plugin:region-1:certificate/123',
                '*:*:*'
            ];
            expect(() => suppress.create(validPatterns)).to.not.throw();
        });

        it('should reject invalid suppression formats', function() {
            const invalidPatterns = [
                'invalid',                    // Missing parts
                'too:many:parts:here',       // Too many parts
                'invalid!:region:resource',   // Invalid characters in pluginId
                'plugin:reg##ion:resource',   // Invalid characters in region
                'plugin:region:res$$ource'    // Invalid characters in resourceId
            ];
            invalidPatterns.forEach(pattern => {
                expect(() => suppress.create([pattern])).to.throw();
            });
        });

        it('should reject overly long patterns', function() {
            const longPattern = 'a'.repeat(65) + ':region:resource';
            expect(() => suppress.create([longPattern])).to.throw();
        });
    });
});
