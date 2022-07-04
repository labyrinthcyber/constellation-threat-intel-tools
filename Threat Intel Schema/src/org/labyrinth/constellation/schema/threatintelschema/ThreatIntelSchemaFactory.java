/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.schema.threatintelschema;

import org.labyrinth.constellation.schema.threatintelschema.concept.ThreatIntelConcept;
import au.gov.asd.tac.constellation.graph.Graph;
import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.GraphReadMethods;
import au.gov.asd.tac.constellation.graph.GraphWriteMethods;
import au.gov.asd.tac.constellation.graph.file.GraphDataObject;
import au.gov.asd.tac.constellation.graph.node.GraphNode;
import au.gov.asd.tac.constellation.graph.node.GraphNodeFactory;
import au.gov.asd.tac.constellation.graph.schema.Schema;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept.ConstellationViewsConcept;
import au.gov.asd.tac.constellation.graph.schema.SchemaFactory;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaTransactionType;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.AnalyticSchemaFactory;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.utilities.visual.VisualManager;
import au.gov.asd.tac.constellation.utilities.icon.AnalyticIconProvider;
import au.gov.asd.tac.constellation.utilities.icon.ConstellationIcon;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;
import org.openide.windows.TopComponent;

@ServiceProvider(service = SchemaFactory.class, position = Integer.MAX_VALUE - 5)
public class ThreatIntelSchemaFactory extends AnalyticSchemaFactory {

    public static final String THREAT_INTEL_SCHEMA_ID = "org.labyrinth.constellation.schema.threatintelschema.ThreatIntelSchemaFactory";

    private static final ConstellationIcon ICON_SYMBOL = AnalyticIconProvider.NETWORK;
    private static final ConstellationColor ICON_COLOR = ConstellationColor.DARK_ORANGE;

    @Override
    public String getName() {
        return THREAT_INTEL_SCHEMA_ID;
    }

    @Override
    public String getLabel() {
        return "Threat Intel Graph";
    }

    @Override
    public String getDescription() {
        return "This schema provides support for Threat Intelligence concepts";
    }

    @Override
    public ConstellationIcon getIconSymbol() {
        return ICON_SYMBOL;
    }

    @Override
    public ConstellationColor getIconColor() {
        return ICON_COLOR;
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getRegisteredConcepts() {
        final Set<Class<? extends SchemaConcept>> registeredConcepts = new HashSet<>();
        registeredConcepts.add(ConstellationViewsConcept.class);
        registeredConcepts.add(VisualConcept.class);
        registeredConcepts.add(AnalyticConcept.class);
        registeredConcepts.add(ThreatIntelConcept.class);
        return Collections.unmodifiableSet(registeredConcepts);
    }

    @Override
    public List<SchemaAttribute> getKeyAttributes(final GraphElementType elementType) {
        final List<SchemaAttribute> keys;
        switch (elementType) {
            case VERTEX:
                keys = Arrays.asList(
                        VisualConcept.VertexAttribute.IDENTIFIER,
                        AnalyticConcept.VertexAttribute.TYPE);
                break;
            case TRANSACTION:
                keys = Arrays.asList(VisualConcept.TransactionAttribute.IDENTIFIER,
                        AnalyticConcept.TransactionAttribute.TYPE,
                        TemporalConcept.TransactionAttribute.DATETIME);
                break;
            default:
                keys = Collections.emptyList();
                break;
        }

        return Collections.unmodifiableList(keys);
    }

    @Override
    public Schema createSchema() {
        return new ThreatIntelSchema(this);
    }

    //Check if this is needed
    public static class ThreatIntelGraphNode extends GraphNode {

        public ThreatIntelGraphNode(Graph graph, GraphDataObject graphDataObject, TopComponent topComponent, VisualManager visual) {
            super(graph, graphDataObject, topComponent, visual);

        }
    }

    protected class ThreatIntelSchema extends AnalyticSchema implements GraphNodeFactory {

        public ThreatIntelSchema(SchemaFactory factory) {
            super(factory);
        }

        @Override
        public void newGraph(final GraphWriteMethods graph) {
            super.newGraph(graph);
        }

        @Override
        public void newVertex(GraphWriteMethods graph, final int vertex) {
            super.newVertex(graph, vertex);
            completeVertex(graph, vertex);
        }

        @Override
        public void completeVertex(GraphWriteMethods graph, final int vertex) {
            super.completeVertex(graph, vertex);

        }

        @Override
        public SchemaVertexType resolveVertexType(String type) {
            return super.resolveVertexType(type);

        }

        @Override
        public void newTransaction(GraphWriteMethods graph, final int transaction) {
            super.newTransaction(graph, transaction);
        }

        @Override
        public void completeTransaction(GraphWriteMethods graph, final int transaction) {
            super.completeTransaction(graph, transaction);
        }

        @Override
        public SchemaTransactionType resolveTransactionType(String type) {
            return super.resolveTransactionType(type);
        }

        @Override
        public int getVertexAliasAttribute(GraphReadMethods graph) {
            return VisualConcept.VertexAttribute.LABEL.get(graph);
        }

        @Override
        public GraphNode createGraphNode(Graph graph, GraphDataObject gDataObj, TopComponent topComp, VisualManager visMgr) {
            return new ThreatIntelGraphNode(graph, gDataObj, topComp, visMgr);
        }
    }

    private static boolean equals(Object a, Object b) {
        if (a == null) {
            return b == null;
        } else {
            return a.equals(b);
        }
    }
}
