/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataaccess.threatinteltools.plugins.threatminer;

import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.google.gson.Gson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.json.simple.parser.ParseException;
import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class),
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("ThreatMinerPlugin=Threat Miner Enrichment")
public class ThreatMinerPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {
    
    @Override
    public String getName() {
        return "Threat Miner Enrichment";
    }

    @Override
    public String getDescription() {
        return "Query the Threat Miner API to enrich IPs, domains, and file hashes";
    }

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return 3;
    }
    
    public static final String IP_WHOIS = PluginParameter.buildId(ThreatMinerPlugin.class, "ipWHOIS");
    public static final String IP_PDNS = PluginParameter.buildId(ThreatMinerPlugin.class, "ipPDNS");
    public static final String IP_HASH = PluginParameter.buildId(ThreatMinerPlugin.class, "ipHash");
    public static final String IP_REPORT = PluginParameter.buildId(ThreatMinerPlugin.class, "ipReport");
    
    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<BooleanParameterType.BooleanParameterValue> ipWHOIS = BooleanParameterType.build(IP_WHOIS);
        ipWHOIS.setName("IP Address(es) - WHOIS");
        ipWHOIS.setDescription("Returns WHOIS information on IP Addresses and adds them to the node's properties.");
        ipWHOIS.setBooleanValue(false);
        params.addParameter(ipWHOIS);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> ipPDNS = BooleanParameterType.build(IP_PDNS);
        ipPDNS.setName("IP Address(es) - Passive DNS");
        ipPDNS.setDescription("Returns any Passive DNS results and adds them to the graph.");
        ipPDNS.setBooleanValue(false);
        params.addParameter(ipPDNS);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> ipHash = BooleanParameterType.build(IP_HASH);
        ipHash.setName("IP Address(es) - Related Sample Hashes");
        ipHash.setDescription("Returns any hashes of known malware samples related to the IP and adds them to the graph.");
        ipHash.setBooleanValue(false);
        params.addParameter(ipHash);
        
        final PluginParameter<BooleanParameterType.BooleanParameterValue> ipReport = BooleanParameterType.build(IP_REPORT);
        ipReport.setName("IP Address(es) - Related reports");
        ipReport.setDescription("Returns any reports related to the IP and adds them to the graph.");
        ipReport.setBooleanValue(false);
        params.addParameter(ipReport);

//        final PluginParameter<BooleanParameterType.BooleanParameterValue> overwriteGeo = BooleanParameterType.build(OVERWRITE_GEO);
//        overwriteGeo.setName("Overwrite IP geolocation information");
//        overwriteGeo.setDescription("If checked, the geolocation information from Shodan will overwrite the information already on the node.");
//        overwriteGeo.setBooleanValue(false);
//        params.addParameter(overwriteGeo);

//        final PluginParameter<BooleanParameterType.BooleanParameterValue> overwriteGeo = BooleanParameterType.build(OVERWRITE_GEO);
//        overwriteGeo.setName("Overwrite IP geolocation information");
//        overwriteGeo.setDescription("If checked, the geolocation information from Shodan will overwrite the information already on the node.");
//        overwriteGeo.setBooleanValue(false);
//        params.addParameter(overwriteGeo);

        return params;
    }
    
    class ipWHOISResponseDTO {
        int status_code;
        String status_message;
        result[] results;
    }
    
    class result {
        String reverse_name;
        String bgp_prefix;
        String cc;
        String asn;
        String asn_name;
        String org_name;
        String register;
    }
    
    private ipWHOISResponseDTO getQuery(String query) throws IOException, ParseException, InterruptedException {
        ipWHOISResponseDTO responseDTO;

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(query))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            ipWHOISResponseDTO obj = new Gson().fromJson(response.body(), ipWHOISResponseDTO.class);
            responseDTO = obj;

        } catch (IOException | InterruptedException ex) {
            return null;
        }

        return responseDTO;
    }
    
    private String urlFormatter(String type, String identifier, int number) {
        String url = String.format("https://api.threatminer.org/v2/%s.php?q=%s&rt=1", type, identifier, Integer.toString(number));
        return url;
    }
    
    private void queryAPI(final RecordStore query, final PluginInteraction interaction, RecordStore results, boolean ipWHOISBool, boolean ipPDNSBool, boolean ipHashBool, boolean ipReportBool) {
        query.reset();
        
        while (query.next()) {
            try {
                final String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                final String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                // IP Address
                if (type.equals(AnalyticConcept.VertexType.IPV4.toString()) || type.equals(AnalyticConcept.VertexType.IPV6.toString()) || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                    if (ipWHOISBool) {
                        String url = urlFormatter("host", identifier, 1);
                        // api.threatminer.org/v2/host.php?q=216.58.213.110&rt=1
                        ipWHOISResponseDTO response = getQuery(url);
                        
                        if (response == null || response.status_code == 404) {
                            return;
                        }
                        results.add();
                    
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                        
                        for (result result : response.results) {
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, result.reverse_name);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                        }
                    }
                    
                    if (ipPDNSBool) {
                        String url = urlFormatter("host", identifier, 2);
                    }
                    
                    if (ipHashBool) {
                        String url = urlFormatter("host", identifier, 4);
                    }
                    
                    if (ipReportBool) {
                        String url = urlFormatter("host", identifier, 6);
                    }
                }
                // Domain
                
                // File hash
            } catch(Exception ex) {
                System.out.println(ex.getMessage());
            }
            
        }
            
    }
    
    
    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {
        final RecordStore results = new GraphRecordStore();
        final Map<String, PluginParameter<?>> params = parameters.getParameters();

        if (query.size() == 0) {
            return results;
        }
        
        boolean ipWHOISBool = params.get(IP_WHOIS).getBooleanValue();
        boolean ipPDNSBool = params.get(IP_PDNS).getBooleanValue();
        boolean ipHashBool = params.get(IP_HASH).getBooleanValue();
        boolean ipReportBool = params.get(IP_REPORT).getBooleanValue();
        
        queryAPI(query, interaction, results, ipWHOISBool, ipPDNSBool, ipHashBool, ipReportBool);
        
        return results;
    }
    
}
