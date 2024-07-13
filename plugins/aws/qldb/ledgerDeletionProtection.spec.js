var expect = require('chai').expect;
var ledgerDeletionProtection = require('./ledgerDeletionProtection');

const listLedgers = [   
    {
        "Name": "test-ledger",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00" 
    } 
];

const describeLedger = [
    {
        "Name": "test-ledger",
        "Arn": "arn:aws:qldb:us-east-1:000111222333:ledger/test-ledger",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00",
        "PermissionsMode": "STANDARD",
        "DeletionProtection": true,
    },
    {
        "Name": "test-ledger",
        "Arn": "arn:aws:qldb:us-east-1:000111222333:ledger/test-ledger",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00",
        "PermissionsMode": "STANDARD",
        "DeletionProtection": false,
    }
];

const createCache = (ledgers, describeLedger, ledgersErr, describeLedgerErr) => {
    var name = (ledgers && ledgers.length) ? ledgers[0].Name: null;
    return {
        qldb: {
            listLedgers: {
                'us-east-1': {
                    err: ledgersErr,
                    data: ledgers
                },
            },
            describeLedger: {
                'us-east-1': {
                    [name]: {
                        data: describeLedger,
                        err: describeLedgerErr
                    }
                }
            }
        },
    };
};

describe('ledgerDeletionProtection', function () {
    describe('run', function () {
        it('should PASS if QLDB ledger has deletion protection enabled', function (done) {
            const cache = createCache(listLedgers, describeLedger[0]);
            ledgerDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if QLDb ledger does not have deletion protection enabled', function (done) {
            const cache = createCache(listLedgers, describeLedger[1]);
            ledgerDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no QLDB ledgers found', function (done) {
            const cache = createCache([]);
            ledgerDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list  QLDB ledgers', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list QLDB ledgers" });
            ledgerDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

    });
})
