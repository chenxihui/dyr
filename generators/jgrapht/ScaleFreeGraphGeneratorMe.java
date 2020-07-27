/*
 * (C) Copyright 2008-2018, by Ilya Razenshteyn and Contributors.
 *
 * JGraphT : a free Java graph-theory library
 *
 * See the CONTRIBUTORS.md file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the
 * GNU Lesser General Public License v2.1 or later
 * which is available at
 * http://www.gnu.org/licenses/old-licenses/lgpl-2.1-standalone.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR LGPL-2.1-or-later
 */
package generators.jgrapht;

import org.jgrapht.*;
import org.jgrapht.generate.GraphGenerator;

import com.sun.prism.impl.Disposer.Target;

import java.util.*;

/**
 * This is a copy of the class org.jgrapht.generate.ScaleFreeGraphGenerator, 
 * but using two statics variables to keep track of the original generated graph.
 * @author Ema Kepuska
 */
public class ScaleFreeGraphGeneratorMe<V, E>
    implements
    GraphGenerator<V, E, V>
{
    private final int size;
    private final Random rng;
    
    public static List<Integer> DEGREES = new ArrayList<Integer>();
    public static int DEGREE_SUM = 0;

    /**
     * Constructor
     *
     * @param size number of vertices to be generated
     */
    public ScaleFreeGraphGeneratorMe(int size)
    {
        this(size, new Random());
    }

    /**
     * Constructor
     *
     * @param size number of vertices to be generated
     * @param seed initial seed for the random generator
     */
    public ScaleFreeGraphGeneratorMe(int size, long seed)
    {
        this(size, new Random(seed));
    }

    /**
     * Constructor
     *
     * @param size number of vertices to be generated
     * @param rng the random number generator
     */
    public ScaleFreeGraphGeneratorMe(int size, Random rng)
    {
        if (size < 0) {
            throw new IllegalArgumentException("invalid size: " + size + " (must be non-negative)");
        }
        this.size = size;
        this.rng = Objects.requireNonNull(rng, "Random number generator cannot be null");
    }

    /**
     * Generates scale-free network with <tt>size</tt> passed to the constructor.
     *
     * @param target receives the generated edges and vertices; if this is non-empty on entry, the
     *        result will be a disconnected graph since generated elements will not be connected to
     *        existing elements
     * @param resultMap unused parameter, can be null
     */
    @Override
    public void generateGraph(Graph<V, E> target, Map<String, V> resultMap)
    {
        List<V> vertexList = new ArrayList<>();
        //List<Integer> degrees = new ArrayList<>();
        //int degreeSum = 0;
        for (int i = 0; i < size; i++) {
            V newVertex = target.addVertex();
            int newDegree = 0;
            while ((newDegree == 0) && (i != 0)) // we want our graph to be connected
            {
                for (int j = 0; j < vertexList.size(); j++) {
                    if ((DEGREE_SUM == 0) || (rng.nextInt(DEGREE_SUM) < DEGREES.get(j))) {
                    	DEGREES.set(j, DEGREES.get(j) + 1);
                        newDegree++;
                        DEGREE_SUM += 2;
                        if (rng.nextBoolean()) {
                            target.addEdge(vertexList.get(j), newVertex);
                        } else {
                            target.addEdge(newVertex, vertexList.get(j));
                        }
                    }
                }
            }
            vertexList.add(newVertex);
            DEGREES.add(newDegree); 
        }
    }
   
}