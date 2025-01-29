/*
 Template Name: Zoogler - Bootstrap 4 Admin Dashboard
 Author: Mannatthemes
 Website: www.mannatthemes.com
 File: Datatable js
 */
 
 $("document").ready(function() {
  $('#datatable').DataTable();

  $(document).ready(function() {
      $('#datatable2').DataTable();  
  });

  $('#datatable-buttons2').dataTable({
    lengthChange: false,
    "searching": true,
    buttons: ['copy', 'excel','pdf', 'colvis']
    
});
var table = $('#datatable-buttons2').DataTable();

table.buttons().container()
      .appendTo('#datatable-buttons2_wrapper .col-md-6:eq(0)');



  //Buttons examples
  $('#datatable-buttons').dataTable({
      lengthChange: false,
      "searching": true,
      buttons: ['copy', 'excel','pdf']
      
  });
  var table = $('#datatable-buttons').DataTable();
  
  if ($('#status-filter').length > 0) {
    // Only apply this block of code if status-filter is present

    $("#filterTable_filter.dataTables_filter").append($("#status-filter"));

    var categoryIndex1 = 0;
    $("#datatable-buttons th").each(function (i) {
        if ($($(this)).html() == "Status") {
            categoryIndex1 = i; 
            return false;
        }
    });

    $.fn.dataTable.ext.search.push(
        function (settings, data, dataIndex) {
            var selectedItem = $('#status-filter').val()
            var category = data[categoryIndex1];
            if (selectedItem === "" || category.includes(selectedItem)) {
                return true;
            }
            return false;
        }
    );

    $("#status-filter").change(function (e) {
        table.draw();
    });

    table.draw();
}

if ($('#service-dropdown').length > 0) {
  // Only apply this block of code if service-dropdown is present

  $("#filterTable_filter.dataTables_filter").append($("#service-dropdown"));

  var categoryIndex2 = 0;
  $("#datatable-buttons th").each(function (i) {
      if ($($(this)).html() == "Service Name") {
          categoryIndex2 = i; 
          return false;
      }
  });

  $.fn.dataTable.ext.search.push(
      function (settings, data, dataIndex) {
          var selectedItem = $('#service-dropdown').val()
          var category = data[categoryIndex2];
          if (selectedItem === "" || category.includes(selectedItem)) {
              return true;
          }
          return false;
      }
  );

  $("#service-dropdown").change(function (e) {
      table.draw();
  });

  table.draw();
}

if ($('#region-filter').length > 0) {
  // Only apply this block of code if region-filter is present

  $("#filterTable_filter.dataTables_filter").append($("#region-filter"));

  var categoryIndex3 = 0;
  $("#datatable-buttons th").each(function (i) {
      if ($($(this)).html() == "Region") {
          categoryIndex3 = i; 
          return false;
      }
  });

  $.fn.dataTable.ext.search.push(
      function (settings, data, dataIndex) {
          var selectedItem = $('#region-filter').val()
          var category = data[categoryIndex3];
          if (selectedItem === "" || category.includes(selectedItem)) {
              return true;
          }
          return false;
      }
  );

  $("#region-filter").change(function (e) {
      table.draw();
  });

  table.draw();
}

if ($('#severity-filter').length > 0) {
  // Only apply this block of code if severity-filter is present

  $("#filterTable_filter.dataTables_filter").append($("#severity-filter"));

  var categoryIndex4 = 0;
  $("#datatable-buttons th").each(function (i) {
      if ($($(this)).html() == "Severity") {
          categoryIndex4 = i; 
          return false;
      }
  });

  $.fn.dataTable.ext.search.push(
      function (settings, data, dataIndex) {
          var selectedItem = $('#severity-filter').val()
          var category = data[categoryIndex4];
          if (selectedItem === "" || category.includes(selectedItem)) {
              return true;
          }
          return false;
      }
  );

  $("#severity-filter").change(function (e) {
      table.draw();
  });

  table.draw();
}


// azure data tables ------------------------------------------------------------------
if ($('#level-dropdown').length > 0) {
  // Only apply this block of code if level-dropdown is present

  $("#filterTable_filter.dataTables_filter").append($("#level-dropdown"));

  var categoryIndex5 = 0;
  $("#datatable-buttons th").each(function (i) {
      if ($($(this)).html() == "Level") {
          categoryIndex5 = i; 
          return false;
      }
  });

  $.fn.dataTable.ext.search.push(
      function (settings, data, dataIndex) {
          var selectedItem = $('#level-dropdown').val()
          var category = data[categoryIndex5];
          if (selectedItem === "" || category.includes(selectedItem)) {
              return true;
          }
          return false;
      }
  );

  $("#level-dropdown").change(function (e) {
      table.draw();
  });

  table.draw();
}

if ($('#az-service-dropdown').length > 0) {
  // Only apply this block of code if az-service-dropdown is present

  $("#filterTable_filter.dataTables_filter").append($("#az-service-dropdown"));

  var categoryIndex6 = 0;
  $("#datatable-buttons th").each(function (i) {
      if ($($(this)).html() == "Service") {
          categoryIndex6 = i; 
          return false;
      }
  });

  $.fn.dataTable.ext.search.push(
      function (settings, data, dataIndex) {
          var selectedItem = $('#az-service-dropdown').val()
          var category = data[categoryIndex6];
          if (selectedItem === "" || category.includes(selectedItem)) {
              return true;
          }
          return false;
      }
  );

  $("#az-service-dropdown").change(function (e) {
      table.draw();
  });

  table.draw();
}


  table.buttons().container()
      .appendTo('#datatable-buttons_wrapper .col-md-6:eq(0)');
} );