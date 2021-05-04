var expect = require('chai').expect;
var plugin = require('./excessiveFirewallRules');

const createCache = (err, data) => {
    return {
        firewalls: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('excessiveFirewallRules', function () {
    describe('run', function () {
        it('should give unknown result if a firewall error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query firewall rules');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no firewall rules found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No firewall rules found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if excessive number of firewall rules are present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Excessive');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give warning result if large number of firewall rules are present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('Large');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },
                  {
                    id: "8212979312924624092",
                  },
                  {
                    id: "6488532437295615846",
                  },
                  {
                    id: "8442800633521702578",
                  },
                  {
                    id: "4111718641158512144",
                  },     
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if acceptable number of firewall rules are present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Acceptable');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                      id: "8212979312924624092",
                    },
                    {
                      id: "6488532437295615846",
                    },
                    {
                      id: "8442800633521702578",
                    },
                    {
                      id: "4111718641158512144",
                    },
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});