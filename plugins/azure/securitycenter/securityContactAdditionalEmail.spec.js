var expect = require('chai').expect;
var securityContactAdditionalEmail = require('./securityContactAdditionalEmail');

const securityContacts = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'On',
        'emails': 'xyz@gmail.com;abc@email.com'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'Off',
        'emails': ''
    }
];

const createCache = (securityContacts) => {
    return {
        securityContactv2: {
            listAll: {
                global:{
                    data: securityContacts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        securityContactv2: {
            listAll: {
                global: {}
            }
        }
    };
};

describe('securityContactAdditionalEmail', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const cache = createCache([]);
            securityContactAdditionalEmail.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function(done) {
            const cache = createErrorCache();
            securityContactAdditionalEmail.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if additional email is configured', function(done) {
            const cache = createCache([securityContacts[0]]);
            securityContactAdditionalEmail.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Additional email address is configured with security contact email');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if additional email is not configured', function(done) {
            const cache = createCache([securityContacts[1]]);
            securityContactAdditionalEmail.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Additional email address is not configured with security contact email');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});