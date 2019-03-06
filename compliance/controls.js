module.exports = {
    create: function (names) {
        // We we don't have a specified compliance, then include all plugins
        if (names.length == 0) {
            return require('./all.js');
        }

        if (names.includes('hipaa')) {
            console.log('INFO: Compliance mode: HIPAA');
            return require('./hipaa.js');
        } else if (names.includes('pci')) {
            console.log('INFO: Compliance mode: PCI');
            return require('./pci.js');
        } else if (names.includes('cis')) {
            console.log('INFO: Compliance mode: CIS');
            return require('./cis.js');
        } else if (names.includes('cis-1')) {
            console.log('INFO: Compliance mode: CIS Profile 1');
            var cis = require('./cis.js');
            cis.setMaxProfile(1);
            return cis;
        } else if (names.includes('cis-2')) {
            console.log('INFO: Compliance mode: CIS Profile 2');
            var cis = require('./cis.js');
            cis.setMaxProfile(2);
            return cis;
        }

        return null;
    }
}