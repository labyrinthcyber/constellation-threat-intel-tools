/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataaccess.threatinteltools.plugins.shodan;

import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.SpatialConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import org.openide.util.NbBundle;
import org.json.simple.parser.ParseException;
import com.google.gson.Gson;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Map;
import org.labyrinth.constellation.schema.threatintelschema.concept.ThreatIntelConcept;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class),
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("ShodanPlugin=Shodan Enrichment")
public class ShodanPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    @Override
    public String getName() {
        return "Shodan Enrichment";
    }

    @Override
    public String getDescription() {
        return "Query IP addresses via the Shodan API";
    }

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return 2;
    }

    public static final String PORTS_OWN_NODE = PluginParameter.buildId(ShodanPlugin.class, "portsOwnNode");
    public static final String OVERWRITE_GEO = PluginParameter.buildId(ShodanPlugin.class, "overwriteGeo");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<BooleanParameterType.BooleanParameterValue> portsOwnNode = BooleanParameterType.build(PORTS_OWN_NODE);
        portsOwnNode.setName("Add open ports to graph");
        portsOwnNode.setDescription("Open ports become their own node on the graph. If unchecked, open ports will be a property of the IP.");
        portsOwnNode.setBooleanValue(false);
        params.addParameter(portsOwnNode);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> overwriteGeo = BooleanParameterType.build(OVERWRITE_GEO);
        overwriteGeo.setName("Overwrite IP geolocation information");
        overwriteGeo.setDescription("If checked, the geolocation information from Shodan will overwrite the information already on the node.");
        overwriteGeo.setBooleanValue(false);
        params.addParameter(overwriteGeo);

        return params;
    }

    class shodanGetIPResponseDTO {

        String region_code;
        String[] tags;
        String ip;
        String area_code;
        String[] domains;
        String[] hostnames;
        String country_code;
        String org;
        String[] data;
        String asn;
        String city;
        float latitude;
        String isp;
        float longitude;
        // Change to date format if possible
        String last_update;
        String[] vulns;
        String country_name;
        String ip_str;
        String os;
        int[] ports;

    }

    String getToken(final PluginInteraction interaction) {
        Properties prop = new Properties();
        File configFile = new File(System.getProperty("user.home") + "/.config/constellation/constellation.conf");
        String token = "";

        try {
            FileReader reader = new FileReader(configFile);
            prop.load(reader);
            token = prop.getProperty("SHODAN_TOKEN");
        } catch (FileNotFoundException ex) {
            interaction.notify(PluginNotificationLevel.FATAL, "The config file containing SHODAN_TOKEN was not found. Please ensure the config file is located at '~/.config/constellation/constellation.conf'");
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return token;
    }

    private shodanGetIPResponseDTO getQuery(String query) throws IOException, ParseException, InterruptedException {
        shodanGetIPResponseDTO responseDTO;

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(query))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            shodanGetIPResponseDTO obj = new Gson().fromJson(response.body(), shodanGetIPResponseDTO.class);
            responseDTO = obj;

        } catch (IOException | InterruptedException ex) {
            return null;
        }

        return responseDTO;
    }

    private void queryAPI(final RecordStore query, final PluginInteraction interaction, RecordStore results, String token, boolean showAVResults, boolean overwriteGeo) {
        query.reset();

        while (query.next()) {
            try {

                final String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                final String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                if (type.equals(AnalyticConcept.VertexType.IPV4.toString()) || type.equals(AnalyticConcept.VertexType.IPV6.toString()) || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                    String getIP = "/shodan/host/";
                    String url = String.format("%s%s%s?key=%s&minify=true", "https://api.shodan.io", getIP, identifier, token);
                    shodanGetIPResponseDTO response = getQuery(url);
                    if (response == null) {
                        return;
                    }
                    results.add();
                    
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    
                    if (overwriteGeo) {
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, response.country_code);
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, response.city);
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, response.latitude);
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, response.longitude);
                        results.set(GraphRecordStoreUtilities.SOURCE + ShodanConcept.VertexAttribute.ISP, response.isp);
                        results.set(GraphRecordStoreUtilities.SOURCE + ShodanConcept.VertexAttribute.ASN, response.asn);
                    }
                    
                    if (response.vulns.length > 0) {
                        results.set(GraphRecordStoreUtilities.SOURCE + ShodanConcept.VertexAttribute.VULNERABILITIES, Arrays.toString(response.vulns).replaceAll("\\[|\\]|\\s", ""));
                    }

                    for (String hostname : response.hostnames) {
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, hostname);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);
                        
                        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, response.last_update);
                        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, ConstellationColor.DARK_ORANGE);

                    }

                    if (showAVResults) {
                        for (int port : response.ports) {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, port);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, ThreatIntelConcept.VertexType.PORT);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, ShodanConcept.TransactionType.OPENPORT);
                            results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, response.last_update);
                        }
                    } else if (!showAVResults) {
                        Arrays.sort(response.ports);
                        results.set(GraphRecordStoreUtilities.SOURCE + ShodanConcept.VertexAttribute.OPENPORTS, Arrays.toString(response.ports).replaceAll("\\[|\\]|\\s", ""));
                    }

                }
            } catch (IOException | InterruptedException | ParseException ex) {
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

        //Get Shodan Token
        String token = getToken(interaction);

        if ("".equals(token)) {
            interaction.notify(PluginNotificationLevel.FATAL, "Config file '~/.config/constellation/constellation.conf' does not contain the IPINFO_TOKEN. Please fix and try again.");
        }

        boolean showAVResults = params.get(PORTS_OWN_NODE).getBooleanValue();
        boolean overwriteGeo = params.get(OVERWRITE_GEO).getBooleanValue();

        queryAPI(query, interaction, results, token, showAVResults, overwriteGeo);

        return results;
    }

}
