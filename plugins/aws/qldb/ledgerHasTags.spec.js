var expect = require('chai').expect;
var ledgerHasTags = require('./ledgerHasTags');

const listLedgers = [   
    {
        "Name": "test-ledger",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00" 
    } 
];

const getResources = [
    {
        "ResourceARN": "arn:aws:qldb:us-east-1:000111222333:ledger/test-ledger",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:qldb:us-east-1:000111222333:ledger/test-ledger",
        "Tags": [{key: 'value'}],
    }
]

const createCache = (ledgers, rgData, ledgersErr) => {
    var name = (ledgers && ledgers.length) ? ledgers[0].Name: null;
    return {
        qldb: {
            listLedgers: {
                'us-east-1': {
                    err: ledgersErr,
                    data: ledgers
                },
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '000111222333'
                }
            }
        }
    };
};

describe('ledgerHasTags', function () {
    describe('run', function () {
        it('should PASS if QLDB ledger has tags', function (done) {
            const cache = createCache(listLedgers, [getResources[1]]);
            ledgerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if QLDb ledger does not have tags', function (done) {
            const cache = createCache(listLedgers, [getResources[0]]);
            ledgerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no QLDB ledgers found', function (done) {
            const cache = createCache([]);
            ledgerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list  QLDB ledgers', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list QLDB ledgers" });
            ledgerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listLedgers[0]],null);
            ledgerHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });

    });
})
