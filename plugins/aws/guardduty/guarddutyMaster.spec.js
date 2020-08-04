var assert = require('assert');
var expect = require('chai').expect;
var guarddutyMaster = require('./guarddutyMaster')

describe('guarddutyMaster', function () {
    describe('run', function () {
        it('should FAIL when guard duty master is incorrect', function () {
            const settings = {
                guardduty_master_account: '123412341234',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                    getMasterAccount: {
                        'us-east-1': {
                            'id123': {
                                data: {
                                    Master: {
                                        AccountId: '123123123123',
                                        InvitationId: 'eab27ad3a037f8639b102a36506f0137',
                                        RelationshipStatus: 'Enabled',
                                        InvitedAt: '2018-08-01T13:22:16.304Z'
                                    },
                                },
                            },
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            });
        });
        it('should PASS when guard duty master is correct', function () {
            const settings = {
                guardduty_master_account: '123412341234',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                    getMasterAccount: {
                        'us-east-1': {
                            'id123': {
                                data: {
                                    Master: {
                                        AccountId: '123412341234',
                                        InvitationId: 'abcd1234abcd1234abcd1234abcd1234',
                                        RelationshipStatus: 'Enabled',
                                        InvitedAt: '2000-01-01T00:00:00.000Z'
                                    },
                                },
                            },
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });
        it('should PASS when guard duty master is correct', function () {
            const settings = {
                guardduty_master_account: '',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                    getMasterAccount: {
                        'us-east-1': {
                            'id123': {
                                data: {
                                    Master: {
                                        AccountId: '123412341234',
                                        InvitationId: 'abcd1234abcd1234abcd1234abcd1234',
                                        RelationshipStatus: 'Enabled',
                                        InvitedAt: '2000-01-01T00:00:00.000Z'
                                    },
                                },
                            },
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });
        it('should FAIL when guard duty master is not set up', function () {
            const settings = {
                guardduty_master_account: '123412341234',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                    getMasterAccount: {
                        'us-east-1': {
                            'id123': {
                                data: {},
                            },
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            });
        });
        it('should FAIL when guard duty master is invited but not confirmed', function () {
            const settings = {
                guardduty_master_account: '123412341234',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                    getMasterAccount: {
                        'us-east-1': {
                            'id123': {
                                data: {
                                    Master: {
                                        AccountId: '123412341234',
                                        InvitationId: 'abcd1234abcd1234abcd1234abcd1234',
                                        RelationshipStatus: 'Invited',
                                        InvitedAt: '2000-01-01T00:00:00.000Z'
                                    },
                                },
                            },
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            });
        });
        it('should FAIL when no guard duty detectors are found', function () {
            const settings = {
                guardduty_master_account: '123412341234',
            };
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: [],
                        },
                    },
                },
            };
            guarddutyMaster.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No GuardDuty detectors found')
            });
        });
    });
});
