var IMAGE_NAME = 0;
var CVE = 1
var SEV = 2 
var VULN_VER = 3
var FIX_VER = 4
var URL = 5

// Colour Scale
CRIT = "#cc3300"
HIGH = "#B35512"
MED = "#ffcc00"
LOW = "#93CAED"
UNKNOWN = "black"

colourPallete = d3.schemeSet1     


var secPieChart = new dc.PieChart("#sev-pie-chart");
var fixPieChart = new dc.PieChart("#fix-pie-chart");
var applicationPieChart = new dc.PieChart("#app-pie-chart");
var cvePieChart = new dc.PieChart("#origin-pie-chart");
var ageChart = new dc.BarChart("#year-histo");
var listTable   = new dc.DataTable("#list-table");


d3.json("./anchore_security/anchore_security.json").then(function (vulns) {

    var ndx = crossfilter(vulns.data)

    // Sev pie chart
    var sevDimension = ndx.dimension(function (d) { 
        return d[SEV]; 
    })
    sevSumGroup = sevDimension.group();

    secPieChart
        .height(480)
        .slicesCap(5)
        .dimension(sevDimension)
        .group(sevSumGroup)
        .legend(dc.legend().highlightSelected(true))
        // .ordinalColors(['red','orange','yellow', 'blue', 'green'])
        .getColor = function(d){
            switch(d.key){
                case "Critical":
                    return CRIT;
                case "High":
                    return HIGH;
                case "Medium":
                    return MED;
                case "Low":
                    return LOW;
                default:
                    console.log("Unknown severity", d[SEV])
                    return UNKNOWN;
            }
        }

    // Fix available pie chart
    var fixDimension = ndx.dimension(function (d) { 
        if(d[FIX_VER] != "None"){
            return "Yes"
        }else{
            return "None"
        }
        
    })
    fixSumGroup = fixDimension.group();

    fixPieChart
        .height(480)
        .slicesCap(2)
        .dimension(fixDimension)
        .group(fixSumGroup)
        .legend(dc.legend().highlightSelected(true))
        .ordinalColors(colourPallete);

    function getOrigin(url){
        if(url.toLowerCase().includes("redhat")){
            return "Red Hat"
        }else if(url.toLowerCase().includes("github")){
            return "Git Hub"
        }else if(url.toLowerCase().includes("nist")){
            return "NIST"
        }else{
            console.log("Unknown CVE database", url)
            return "Other"
        }
    }

    // cve pie chart
    var cveDimension = ndx.dimension(function (d) { 
        return getOrigin(d[URL])
    })
    cveSumGroup = cveDimension.group();

    cvePieChart
        .height(480)
        .dimension(cveDimension)
        .group(cveSumGroup)
        .legend(dc.legend().highlightSelected(true))
        .ordinalColors(colourPallete);

    // application pie chart
    var applicationDimension = ndx.dimension(function (d) { 
        return /(.*\/)(.*)(:.*$)/.exec(d[IMAGE_NAME])[2]
    })
    applicationSumGroup = applicationDimension.group();

    applicationPieChart
        .height(480)
        .dimension(applicationDimension)
        .group(applicationSumGroup)
        .legend(dc.legend().highlightSelected(true))
        .ordinalColors(colourPallete);
        
    
    // Age of CVE bar chart
    ageDim = ndx.dimension(function(d){
        if(d[CVE].toLowerCase().includes("ghsa")){
            return "GitHub"
        }
        return /(^.*-)(.*)(-.*$)/.exec(d[CVE])[2]
    })
    ageGroup = ageDim.group()

    ageChart
        .height(480)
        .x(d3.scaleBand())
        .xUnits(dc.units.ordinal)
        .brushOn(false)
        .dimension(ageDim)
        .group(ageGroup)
        .addFilterHandler(function(filters, filter) {return [filter];}); // this
    
    // Data Table chart
    var dataDim = ndx.dimension(function(d){return [d[IMAGE_NAME], d[CVE], d[SEV], d[VULN_VER], d[FIX_VER], d[URL]]})

    listTable
        .height(480)
        .dimension(dataDim)
        .size(Infinity)
        .columns([
                {
                    label:'Image',
                    format: function(d) {return /[^/]*$/.exec(d[IMAGE_NAME])[0]} 
                },
                {
                    label:'CVE',
                    format: function(d) {return d[CVE]} 
                },
                {
                    label:'Severity',
                    format: function(d) {return d[SEV]} 
                },
                {
                    label:'Current Version',
                    format: function(d) {return d[VULN_VER]} 
                },
                {
                    label:'Fix Version',
                    format: function(d) {return d[FIX_VER]} 
                },
                {
                    label:'Link',
                    format: function(d) {
                        origin = getOrigin(d[URL])
                        return d[URL].replace(/>http.*</, ">"+origin+"<")
                    }
                },
            ])
        .sortBy(function (d) { 
            switch(d[SEV]){
                case "Critical":
                    return 0;
                case "High":
                    return 1;
                case "Medium":
                    return 2;
                case "Low":
                    return 3;
                default:
                    console.log("Unknown severity", d[SEV])
                    return 50;
            }
        })

    
    dc.renderAll();

    
});



