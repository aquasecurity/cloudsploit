var expect = require('chai').expect;
var bastionHostHasTags = require('./bastionHostHasTags.js');

const listBastionHost = [
    {
      name: "bastionhost'",
      id: "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/bastionHosts/bastionhosttenant'",
      type: "Microsoft.Network/bastionHosts",
      location: "West US",
      sku: {
        name: "Standard"
      },
      tags:{}
    },
    {
      name: "bastionhost12'",
      id: "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/bastionHosts/bastionhosttenant'",
      type: "Microsoft.Network/bastionHosts",
      location: "West US",
      sku: {
        name: "Standard"
      },
      tags:{
        abc: "123"
      }
    }
];


const createCache = (listBastionHosts) => {
    return {
        bastionHosts: {
            listAll: {
                'eastus':  { data: listBastionHosts}
            }
        }
    };
};


describe('bastionHostHasTags', function () {
    describe('run', function () {

        it('should give a passing result if no Bastion Hosts are found', function (done) {
            const cache = createCache([], null);
            bastionHostHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Bastion hosts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Bastion hosts', function (done) {
            const cache = createCache(null, ['error']);
            bastionHostHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Bastion Host');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Bastion host has tags', function (done) {
            const cache = createCache([listBastionHost[1]], null);
            bastionHostHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bastion Host has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Bastion host does not have tags', function (done) {
            const cache = createCache([listBastionHost[0]], null);
            bastionHostHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bastion Host does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});