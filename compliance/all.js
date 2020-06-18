// Defines a way of filters that includes all rules. This is the default
// compliance filter if there is no other defined filter.
module.exports = {
    describe: function() {
        return '';
    },

    includes: function() {
        // We include all plugins, so just return true
        return true;
    }
};
