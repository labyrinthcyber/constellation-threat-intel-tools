/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataccess.threatinteltools.plugins.ipinfo;

import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.SpatialConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;
import io.ipinfo.api.IPinfo;
import io.ipinfo.api.errors.RateLimitedException;
import io.ipinfo.api.model.IPResponse;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import org.openide.util.NbBundle;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class),
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("IPInfoPlugin=IPInfo Enrichment")
public class IPInfoPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    @Override
    public String getName() {
        return "IPInfo Enrichment";
    }

    @Override
    public String getDescription() {
        return "Query IPInfo API";
    }

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return 1;
    }

    String getToken(final PluginInteraction interaction) {
        Properties prop = new Properties();
        File configFile = new File(System.getProperty("user.home") + "/.config/constellation/constellation.conf");
        System.out.println(configFile);
        String token = "";

        try {
            FileReader reader = new FileReader(configFile);
            prop.load(reader);
            token = prop.getProperty("IPINFO_TOKEN");
        } catch (FileNotFoundException ex) {
            interaction.notify(PluginNotificationLevel.FATAL, "The config file containing IPINFO_TOKEN was not found. Please ensure the config file is located at '~/.config/constellation/constellation.conf'");
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return token;
    }

    private void queryAPI(final RecordStore query, final PluginInteraction interaction, RecordStore results, String token) {
        query.reset();
                
        while (query.next()) {
            try {
                final String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                final String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                System.out.println(identifier);
                if (type.equals(AnalyticConcept.VertexType.IPV4.toString()) || type.equals(AnalyticConcept.VertexType.IPV6.toString()) || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                    IPinfo ipInfo = new IPinfo.Builder()
                    .setToken(token)
                    .build();
                    
                    IPResponse response = ipInfo.lookupIP(identifier);
                    System.out.println(response.toString());
                    
                    if (response.getHostname() != null) {
                        
                        results.add();
                        
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, response.getCountryCode());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, response.getCity());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, response.getLatitude());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, response.getLongitude());
                        
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, response.getHostname());
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);
                        
                        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.DIRECTED, "TRUE");
                        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.COLOR, ConstellationColor.EMERALD);
                        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                    }
                    else {
                        results.add();
                        
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, response.getCountryCode());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, response.getCity());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, response.getLatitude());
                        results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, response.getLongitude());
                    }
                }
                
            } catch (RateLimitedException ex) {
                interaction.notify(PluginNotificationLevel.FATAL, "Rate limit reached. Try again in a while.");
                }

        }
    }

        @Override
        protected RecordStore query
        (final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {
            final RecordStore results = new GraphRecordStore();

            if (query.size() == 0) {
                return results;
            }

            //Get IPInfo Token
            String token = getToken(interaction);

            if ("".equals(token)) {
                interaction.notify(PluginNotificationLevel.FATAL, "Config file '~/.config/constellation/constellation.conf' does not contain the IPINFO_TOKEN. Please fix and try again.");
            }

            queryAPI(query, interaction, results, token);
            
            
            return results;
        }

    }
