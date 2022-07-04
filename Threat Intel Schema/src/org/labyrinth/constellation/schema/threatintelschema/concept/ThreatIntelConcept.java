/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.schema.threatintelschema.concept;

import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import org.openide.util.lookup.ServiceProvider;
import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.LongObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.utilities.icon.AnalyticIconProvider;
import org.labyrinth.constellation.schema.threatintelschema.icons.ThreatIntelIconProvider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@ServiceProvider(service = SchemaConcept.class)
public class ThreatIntelConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Threat Intel";
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return Collections.unmodifiableSet(parentSet);
    }

    public static class VertexType {

        public static final SchemaVertexType CVE = new SchemaVertexType.Builder("CVE")
                .setForegroundIcon(AnalyticIconProvider.INVADER)
                .build();

        public static final SchemaVertexType PORT = new SchemaVertexType.Builder("Port")
                .setForegroundIcon(AnalyticIconProvider.SIGNAL)
                .setColor(ConstellationColor.TEAL)
                .build();
    }

    @Override
    public List<SchemaVertexType> getSchemaVertexTypes() {
        final List<SchemaVertexType> schemaVertexTypes = new ArrayList<>();
        schemaVertexTypes.add(VertexType.CVE);
        schemaVertexTypes.add(VertexType.PORT);
        return Collections.unmodifiableList(schemaVertexTypes);
    }

    public static class TransactionAttribute {

        private TransactionAttribute() {
            // ignore
        }

        public static final SchemaAttribute SRC_PORTS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Source Ports")
                .setDescription("Source Ports")
                .build();

        public static final SchemaAttribute DST_PORTS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Destination Ports")
                .setDescription("Destination Ports")
                .build();

        public static final SchemaAttribute OCTETS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Octets")
                .setDescription("Octets")
                .build();

        public static final SchemaAttribute FLOW_COUNT = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Flow Count")
                .setDescription("Flow Count")
                .build();

        public static final SchemaAttribute PACKETS = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, LongObjectAttributeDescription.ATTRIBUTE_NAME, "Packets")
                .setDescription("Packets")
                .build();

        public static final SchemaAttribute PROTOCOL = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Protocol")
                .setDescription("Protocol")
                .build();

    }

    public static class VertexAttribute {

        public static final SchemaAttribute COUNT = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Count")
                .setDescription("Count")
                .build();

        public static final SchemaAttribute MD5 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "MD5")
                .setDescription("MD5 Hash")
                .build();

        public static final SchemaAttribute SHA1 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SHA1")
                .setDescription("SHA1 Hash")
                .build();

        public static final SchemaAttribute SHA256 = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "SHA256")
                .setDescription("SHA256 Hash")
                .build();

        public static final SchemaAttribute PROTOCOL = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Protocol")
                .setDescription("Protocol")
                .build();

        public static final SchemaAttribute SIZE = new SchemaAttribute.Builder(GraphElementType.VERTEX, IntegerObjectAttributeDescription.ATTRIBUTE_NAME, "Size")
                .setDescription("Size")
                .build();
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> attributes = new ArrayList<>();
        attributes.add(VertexAttribute.PROTOCOL);
        attributes.add(TransactionAttribute.PROTOCOL);
        attributes.add(VertexAttribute.MD5);
        attributes.add(VertexAttribute.COUNT);
        attributes.add(TransactionAttribute.PACKETS);
        attributes.add(TransactionAttribute.OCTETS);
        attributes.add(TransactionAttribute.FLOW_COUNT);
        attributes.add(TransactionAttribute.SRC_PORTS);
        attributes.add(TransactionAttribute.DST_PORTS);
        attributes.add(VertexAttribute.SHA1);
        attributes.add(VertexAttribute.SHA256);
        attributes.add(VertexAttribute.SIZE);
        return Collections.unmodifiableCollection(attributes);
    }

}
