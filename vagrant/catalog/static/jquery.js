//jquery.js

var c1=0;
$(function() {
      $("#cat1").click( function()
           {
             c1++;
             alert('Cat1 clicked: ' + c1 + ' times');
           }
      );
});

var c2=0;
$(function() {
      $("#cat2").click( function()
           {
             c2++;
             alert('Cat1 clicked: ' + c2 + ' times');
           }
      );
});
