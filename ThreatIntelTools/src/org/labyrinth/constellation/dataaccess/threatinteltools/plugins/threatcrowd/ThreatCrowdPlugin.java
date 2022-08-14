/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataaccess.threatinteltools.plugins.threatcrowd;

import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.parameters.ParameterChange;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.DateTimeRange;
import au.gov.asd.tac.constellation.plugins.parameters.types.DateTimeRangeParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.IntegerParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.IntegerParameterType.IntegerParameterValue;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.CoreGlobalParameters;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.plugins.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.google.gson.Gson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.SimpleDateFormat;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.simple.parser.ParseException;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class),
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("ThreatCrowdPlugin=Threat Crowd Enrichment")
public class ThreatCrowdPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    @Override
    public String getName() {
        return "Threat Crowd Enrichment";
    }

    @Override
    public String getDescription() {
        return "Query the Threat Crowd API to enrich IPs, domains, and file hashes";
    }

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return 3;
    }

    public static final String EMAIL = PluginParameter.buildId(ThreatCrowdPlugin.class, "email");
    public static final String HASHES = PluginParameter.buildId(ThreatCrowdPlugin.class, "hashes");
    public static final String SUBDOMAIN = PluginParameter.buildId(ThreatCrowdPlugin.class, "subdomain");
    public static final String LIMIT = PluginParameter.buildId(ThreatCrowdPlugin.class, "limit");
    public static final String LIMIT_BOOL = PluginParameter.buildId(ThreatCrowdPlugin.class, "limitBool");
    public static final String TIMEBOUND = PluginParameter.buildId(ThreatCrowdPlugin.class, "timebound");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<BooleanParameterType.BooleanParameterValue> timeboundPluginParam = BooleanParameterType.build(TIMEBOUND);
        timeboundPluginParam.setName("Time-bound query");
        timeboundPluginParam.setDescription("Limits results to within the selected time.");
        params.addParameter(timeboundPluginParam);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> limitBoolPluginParam = BooleanParameterType.build(LIMIT_BOOL);
        limitBoolPluginParam.setName("Limit results");
        limitBoolPluginParam.setDescription("Limit number of subdomains/IPs/emails returned (each).");
        params.addParameter(limitBoolPluginParam);

        final PluginParameter<IntegerParameterValue> limitReturnPluginParam = IntegerParameterType.build(LIMIT);
        limitReturnPluginParam.setName("Limit results to: ");
        limitReturnPluginParam.setDescription("");
        IntegerParameterType.setMinimum(limitReturnPluginParam, 1);
        limitReturnPluginParam.setIntegerValue(10);
        limitReturnPluginParam.setEnabled(false);
        params.addParameter(limitReturnPluginParam);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> subdomainPluginParam = BooleanParameterType.build(SUBDOMAIN);
        subdomainPluginParam.setName("Add subdomains to graph");
        subdomainPluginParam.setDescription("Adds known subdomains of a domain to the graph.");
        subdomainPluginParam.setBooleanValue(false);
        params.addParameter(subdomainPluginParam);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> hashesPluginParam = BooleanParameterType.build(HASHES);
        hashesPluginParam.setName("Add hashes to graph");
        hashesPluginParam.setDescription("Adds associated of a domain or IP to the graph.");
        hashesPluginParam.setBooleanValue(false);
        params.addParameter(hashesPluginParam);

        final PluginParameter<BooleanParameterType.BooleanParameterValue> emailPluginParam = BooleanParameterType.build(EMAIL);
        emailPluginParam.setName("Add emails to graph");
        emailPluginParam.setDescription("Adds associated emails of a domain or IP to the graph.");
        emailPluginParam.setBooleanValue(false);
        params.addParameter(emailPluginParam);

        final PluginParameter<DateTimeRangeParameterType.DateTimeRangeParameterValue> dtParam = CoreGlobalParameters.DATETIME_RANGE_PARAMETER;
        params.addParameter(dtParam);

        params.addController(LIMIT_BOOL, (master, parameters, change) -> {
            if (change == ParameterChange.VALUE) {
                final boolean masterBoolean = master.getBooleanValue();

                @SuppressWarnings("unchecked")
                final PluginParameter<IntegerParameterValue> limitNum = (PluginParameter<IntegerParameterValue>) parameters.get(LIMIT);
                limitNum.setEnabled(masterBoolean);
            }
        });

        return params;
    }

    class responseDTO {

        int response_code;
        List<resolution> resolutions;
        List<String> hashes;
        List<String> emails;
        List<String> subdomains;
        List<String> references;
        int votes;
        String permalink;
    }

    class resolution implements Comparable<resolution> {

        String last_resolved;
        String ip_address;
        String domain;

        public LocalDate getLastResolved() {
            try {
                return LocalDate.parse(last_resolved);
            } catch (DateTimeException ex) {
                System.out.println(ex);
                return LocalDate.parse("1970-01-01");
            }
        }

        @Override
        public int compareTo(resolution res) {
            if (getLastResolved() == null || res.getLastResolved() == null) {
                return 0;
            }
            return getLastResolved().compareTo(res.getLastResolved());
        }
    }

    private responseDTO getQuery(String type, String identifier) throws IOException, ParseException, InterruptedException {
        responseDTO newResponse;
        String query = String.format("https://www.threatcrowd.org/searchApi/v2/%s/report/?%s=%s", type, type, identifier);

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(query))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return null;
            }

            System.out.println(response);

            responseDTO obj = new Gson().fromJson(response.body(), responseDTO.class);
            newResponse = obj;

        } catch (IOException | InterruptedException ex) {
            return null;
        }

        return newResponse;
    }

    private void queryAPI(final RecordStore query, final PluginInteraction interaction, RecordStore results, boolean hashesBool, boolean emailBool, boolean subdomainBool, boolean limitBool, int limitNum, boolean timeboundBool, long startTime, long endTime) throws java.text.ParseException {
        query.reset();

        while (query.next()) {
            try {
                final String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                final String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                // IP Address

                if (type.equals(AnalyticConcept.VertexType.IPV4.toString()) || type.equals(AnalyticConcept.VertexType.IPV6.toString()) || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                    responseDTO response = getQuery("ip", identifier);

                    if (response.response_code != 1) {
                        return;
                    } else {

                        List<resolution> resTimeboundList = new ArrayList<>();
                        if (timeboundBool) {
                            for (resolution resolution : response.resolutions) {
                                SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
                                Date date = df.parse(resolution.last_resolved);
                                long epoch = date.getTime();
                                if (epoch >= startTime && epoch <= endTime) {
                                    resTimeboundList.add(resolution);
                                }
                            }
                            response.resolutions = resTimeboundList;
                        }

                        Collections.sort(response.resolutions, Collections.reverseOrder());

                        if (limitBool && response.resolutions.size() > limitNum) {
                            response.resolutions = response.resolutions.subList(0, limitNum);
                        }

                        for (resolution resolution : response.resolutions) {

                            results.add();

                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, resolution.domain);

                            final Pattern hostnamePattern = AnalyticConcept.VertexType.HOST_NAME.getValidationRegex();
                            final Matcher hostnameMatcher = hostnamePattern.matcher(resolution.domain);
                            if (hostnameMatcher.matches()) {
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                            }

                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                            results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(resolution.last_resolved));
                        }

                    }
                    if (hashesBool) {
                        if (limitBool && response.hashes.size() > limitNum) {
                            response.hashes = response.hashes.subList(0, limitNum);
                        }

                        for (String hash : response.hashes) {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, hash);

                            final Pattern md5Pattern = AnalyticConcept.VertexType.MD5.getValidationRegex();
                            final Matcher md5Matcher = md5Pattern.matcher(hash);
                            if (md5Matcher.matches()) {
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                            }

                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                        }

                    }
                } else if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString()) || type.equals(AnalyticConcept.VertexType.URL.toString()) || type.equals(AnalyticConcept.VertexType.ONLINE_LOCATION.toString())) {
                    responseDTO response = getQuery("domain", identifier);

//                    System.out.println("Unsorted:\n");
//                    for (resolution resolution : response.resolutions) {
//                        System.out.println(resolution.last_resolved);
//                    }
//                    System.out.println("\n\nsorted:\n");
//                    for (resolution resolution : response.resolutions) {
//                        System.out.println(resolution.last_resolved);
//                    }
                    if (response.response_code != 1) {
                        return;
                    } else {

                        List<resolution> resTimeboundList = new ArrayList<>();

                        if (timeboundBool) {
                            for (resolution resolution : response.resolutions) {
                                SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
                                Date date = df.parse(resolution.last_resolved);
                                long epoch = date.getTime();
                                if (epoch >= startTime && epoch <= endTime) {
                                    resTimeboundList.add(resolution);
                                }
                            }
                            response.resolutions = resTimeboundList;
                        }

                        Collections.sort(response.resolutions, Collections.reverseOrder());

                        if (limitBool && response.resolutions.size() > limitNum) {
                            response.resolutions = response.resolutions.subList(0, limitNum);
                        }

                        for (resolution resolution : response.resolutions) {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, resolution.ip_address);

                            final Pattern ipv6Pattern = AnalyticConcept.VertexType.IPV6.getValidationRegex();
                            final Pattern ipv4Pattern = AnalyticConcept.VertexType.IPV4.getValidationRegex();
                            final Matcher ipv4Matcher = ipv4Pattern.matcher(resolution.ip_address);
                            final Matcher ipv6Matcher = ipv6Pattern.matcher(resolution.ip_address);
                            if (ipv4Matcher.matches()) {
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IPV4);
                            } else if (ipv6Matcher.matches()) {
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IPV6);
                            }
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);
                            results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(resolution.last_resolved));
                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);

                        }
                    }
                    if (emailBool) {

                        if (limitBool && response.emails.size() > limitNum) {
                            response.emails = response.emails.subList(0, limitNum);
                        }

                        for (String email : response.emails) {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, email);

                            final Pattern emailPattern = AnalyticConcept.VertexType.EMAIL_ADDRESS.getValidationRegex();
                            final Matcher emailMatcher = emailPattern.matcher(email);
                            if (emailMatcher.matches()) {
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.EMAIL_ADDRESS);
                            }

                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);
                        }
                    }
                    if (subdomainBool) {

                        if (limitBool && response.subdomains.size() > limitNum) {
                            response.subdomains = response.subdomains.subList(0, limitNum);
                        }

                        for (String subdomain : response.subdomains) {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, subdomain);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, pluginName);

                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.RELATIONSHIP);

                        }
                    }
                }

            } catch (IOException | InterruptedException | ParseException | NullPointerException ex) {
                System.out.println(ex.getMessage());
            } catch (java.text.ParseException ex) {
                Exceptions.printStackTrace(ex);
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

        boolean hashesBool = params.get(HASHES).getBooleanValue();
        boolean emailBool = params.get(EMAIL).getBooleanValue();
        boolean subdomainBool = params.get(SUBDOMAIN).getBooleanValue();
        boolean limitBool = params.get(LIMIT_BOOL).getBooleanValue();
        int limitNum = params.get(LIMIT).getIntegerValue();
        boolean timeboundBool = params.get(TIMEBOUND).getBooleanValue();

        if (timeboundBool) {
            final DateTimeRange datetimeRange = parameters.getDateTimeRangeValue(CoreGlobalParameters.DATETIME_RANGE_PARAMETER_ID);
            final DateTimeRange dtr = parameters.getDateTimeRangeValue(CoreGlobalParameters.DATETIME_RANGE_PARAMETER_ID);
            final ZonedDateTime[] dtrStartEnd = dtr.getZonedStartEnd();
            final long startTime = datetimeRange.getZonedStartEnd()[0].toInstant().toEpochMilli();
            final long endTime = datetimeRange.getZonedStartEnd()[1].toInstant().toEpochMilli();
            System.out.println("DTR:" + dtrStartEnd[0] + dtrStartEnd[1]);
            System.out.println("Start time:" + startTime);
            System.out.println("End time:" + endTime);
            try {
                queryAPI(query, interaction, results, hashesBool, emailBool, subdomainBool, limitBool, limitNum, timeboundBool, startTime, endTime);
            } catch (java.text.ParseException ex) {
                Exceptions.printStackTrace(ex);
            }

        } else {
            try {
                queryAPI(query, interaction, results, hashesBool, emailBool, subdomainBool, limitBool, limitNum, timeboundBool, 0, 0);
            } catch (java.text.ParseException ex) {
                Exceptions.printStackTrace(ex);
            }
        }

        return results;
    }

}
