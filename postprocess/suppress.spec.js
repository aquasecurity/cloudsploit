var expect = require('chai').expect;
var suppress = require('./suppress');

describe('create', function () {
    it('should return undefined when no filter specified', function () {
        var filter = suppress.create([]);

        expect(filter('any')).to.be.undefined;
    });

    it('should return the filter if matches', function () {
        var filter = suppress.create(['*n*']);

        expect(filter('any')).to.equal('*n*');
    });

    it('should return the filter if matches whole word', function () {
        var filter = suppress.create(['*longer*']);

        expect(filter('longer')).to.equal('*longer*');
    });

    it('should return the filter if multiple and second matches', function () {
        var filter = suppress.create(['*first*',
                                      'second']);

        expect(filter('second')).to.equal('second');
    });
});
