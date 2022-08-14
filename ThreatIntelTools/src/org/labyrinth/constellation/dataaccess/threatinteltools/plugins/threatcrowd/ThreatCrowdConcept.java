/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.dataaccess.threatinteltools.plugins.threatcrowd;

import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaTransactionType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class ThreatCrowdConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "ThreatCrowd";
    }

    public static class VertexAttribute {

        private VertexAttribute() {
            // ignore
        }

    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();

        return schemaAttributes;
    }

    @Override
    public List<SchemaTransactionType> getSchemaTransactionTypes() {
        final List<SchemaTransactionType> schemaTransactionTypes = new ArrayList<>();
        //
        return Collections.unmodifiableList(schemaTransactionTypes);
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        //
        return parentSet;
    }
}
