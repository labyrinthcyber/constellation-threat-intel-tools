/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.labyrinth.constellation.schema.threatintelschema.icons;

import au.gov.asd.tac.constellation.utilities.icon.ByteIconData;
import au.gov.asd.tac.constellation.utilities.icon.ConstellationIcon;
import au.gov.asd.tac.constellation.utilities.icon.ConstellationIconProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.openide.util.lookup.ServiceProvider;


@ServiceProvider(service = ConstellationIconProvider.class)
public class ThreatIntelIconProvider implements ConstellationIconProvider {
    
    private static ByteIconData loadIcon(String name) {
        try {
            byte[] bytes = IOUtils.toByteArray(ThreatIntelIconProvider.class.getResourceAsStream(name));
            return new ByteIconData(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ByteIconData(new byte[0]);
    }
    
//    public static final ConstellationIcon <Name> = new ConstellationIcon.Builder("<name>", loadIcon("<filename>.PNG"))
//            .addCategory("ThreatIntel")
//            .build();
    
    @Override
    public List<ConstellationIcon> getIcons() {
        List<ConstellationIcon> threatIntelIcons = new ArrayList<>();
        //threatIntelIcons.add();
        return threatIntelIcons;
    }
}
