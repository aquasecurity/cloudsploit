var expect = require('chai').expect;
var suppress = require('./suppress');

describe('create', function () {
    it('should return undefined when no filter specified', function () {
        var filter = suppress.create([]);
        expect(filter('any')).to.be.undefined;
    });

    it('should return the filter if matches', function () {
        var filter = suppress.create(['p*:us-east-1:n*']);
        expect(filter('plugin123:us-east-1:name')).to.equal('p*:us-east-1:n*');
    });

    it('should return the filter if matches whole word', function () {
        var filter = suppress.create(['plugin123:us-east-1:longer']);
        expect(filter('plugin123:us-east-1:longer')).to.equal('plugin123:us-east-1:longer');
    });

    it('should return the filter if multiple and second matches', function () {
        var filter = suppress.create([
            'plugin123:us-east-1:first*',
            'plugin456:us-west-2:second'
        ]);
        expect(filter('plugin456:us-west-2:second')).to.equal('plugin456:us-west-2:second');
    });
});
