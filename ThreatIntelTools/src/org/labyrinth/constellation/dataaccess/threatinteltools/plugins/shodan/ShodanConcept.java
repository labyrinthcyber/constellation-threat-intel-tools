/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataaccess.threatinteltools.plugins.shodan;

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaTransactionType;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class ShodanConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Shodan";
    }

    public static class VertexAttribute {

        private VertexAttribute() {
            //ignore
        }
        
        public static final SchemaAttribute OPENPORTS = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Open Ports")
                .setDescription("Ports open on this IP.")
                .build();
        
        public static final SchemaAttribute ISP = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ISP")
                .setDescription("ISP of this IP.")
                .build();
        
        public static final SchemaAttribute ASN = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "ASN")
                .setDescription("ASN of the IP.")
                .build();
        
        public static final SchemaAttribute VULNERABILITIES = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Vulnerabilities")
                .setDescription("ASN of the IP.")
                .build();
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        schemaAttributes.add(VertexAttribute.OPENPORTS);
        schemaAttributes.add(VertexAttribute.ISP);
        schemaAttributes.add(VertexAttribute.ASN);
        schemaAttributes.add(VertexAttribute.VULNERABILITIES);
        return schemaAttributes;
    }

    public static class TransactionType {

        public static final SchemaTransactionType OPENPORT = new SchemaTransactionType.Builder("OpenPort")
                .setDescription("A transaction representing an open port on that IP (Supplied by Shodan enrichment)")
                .setColor(ConstellationColor.TEAL)
                .setDirected(Boolean.FALSE)
                .build();
    }

    @Override
    public List<SchemaTransactionType> getSchemaTransactionTypes() {
        final List<SchemaTransactionType> schemaTransactionTypes = new ArrayList<>();
        schemaTransactionTypes.add(TransactionType.OPENPORT);
        return Collections.unmodifiableList(schemaTransactionTypes);
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return parentSet;
    }
}
