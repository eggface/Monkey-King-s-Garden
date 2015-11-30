
Devices = new Mongo.Collection("devices");

if (Meteor.isClient) {
  // This code only runs on the client
    Template.e7_clientes.helpers({
        e7_2_tables: function () {
              return Devices.find({mode: "e7-2"}, {sort: {ver: -1}});
        },

        e7_20_tables: function () {
              return Devices.find({mode: "e7-20"}, {sort: {ver: -1}});
        },

        e3_48c_tables: function () {
              return Devices.find({mode: "e3-48c"}, {sort: {ver: -1}});
        },

        e5_48_tables: function () {
              return Devices.find({mode: {$in: ["e5-48", "e5-48c"]}});
        },

        e3_8g_tables: function () {
              return Devices.find({mode: "e3-8g"}, {sort: {ver: -1}});
        },

        other_tables: function () {
            return Devices.find({mode: {$nin: ["e7-2", "e7-20", "e3-48c", "e5-48", "e5-48c", "e3-8g"]}});
        }
    });

    Template.e7_clientes.e7_tableSettings = function () {
        return {
            //showColumnToggles: true,
            showNavigation: 'never',
            rowsPerPage: 999,
            fields: [
                { key: 'ip', label: 'IP', 
                    fn: function (value) {
                        return new Spacebars.SafeString('<a href="http://'+value+'" target="_blank">'+value+'</a>');
                    }
                },
                { key: 'mode', label: 'Mode' },
                { key: 'schema_version', label: 'Schema Version' },
                { key: 'ver', label: 'Version', cellClass: 'pink_cell',
                    fn: function (value, object) { return value; }
                },
                { key: 'has_dhcp_leases', label: 'DHCP Leases', 
                    cellClass: function (value, object) {
                        if(value == "YES"){
                            var css = 'medium_purple_cell';
                            return css;
                        }
                    }
                },
                { key: 'has_vdsl48c', label: 'VDSL48C Card',
                    cellClass: function (value, object) {
                        if(value == "YES"){
                            var css = 'medium_purple_cell';
                            return css;
                        }
                    }
                },
                { key: 'has_disc_ont', label: 'Discovered ONT',
                    cellClass: function (value, object) {
                        if(value == "YES"){
                            var css = 'medium_purple_cell';
                            return css;
                        }
                    }
                },
                { key: 'has_pppoe_sessions', label: 'PPPoE Sessions',
                    cellClass: function (value, object) {
                        if(value == "YES"){
                            var css = 'medium_purple_cell';
                            return css;
                        }
                    }
                },
                { key: 'ont_with_rgwan', label: 'ONT ID With RG-Wan',
                    cellClass: function (value, object) {
                        if(value){
                            var css = 'medium_purple_cell';
                            return css;
                        }
                    }
                },
                { key: 'create_time', label: 'Sniffer Time'}
            ]
        };
    }

    //Template.e7_device.rendered = function (){
        //alert("in rendered");
        //console.log($("td:contains('YES')"));
      //$( "td").contains('YES').css({ backgroundColor: "MediumPurple"});
      //$( "td:contains('YES')").css({ backgroundColor: "MediumPurple"});
        //alert("after rendered");
    //}
}
