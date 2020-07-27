
package GraphGeneratorsDemo;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.Random;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.generate.GnmRandomBipartiteGraphGenerator;
import org.jgrapht.generate.GnpRandomBipartiteGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.traverse.DepthFirstIterator;
import org.jgrapht.util.SupplierUtil;



public class GnmRandomBipartiteDemo {
	
	static final int n1=100;
	static final int n2=100;
	static final int m= 5000;	
	static final Random seed= new Random();
	
	 /* @param n1 number of vertices of the first partition
     * @param n2 number of vertices of the second partition
     * @param m the number of edges
     * @param seed seed for the random number generator
     */
	
public static void main(String []arg) throws FileNotFoundException {	
	   Supplier<String> vSupplier = new Supplier<String>()
       {
           private int id = 0;

           @Override
           public String get()
           {
               return "v" + id++;
           }
       };
       
      Graph<String, DefaultEdge> randomBipartiteGraph =
	            new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
      GnmRandomBipartiteGraphGenerator<String, DefaultEdge> GBPGenerator= new GnmRandomBipartiteGraphGenerator<String, DefaultEdge>(n1, n2, m, seed);

      GBPGenerator.generateGraph(randomBipartiteGraph);
      
   	PrintStream o = new PrintStream(new File("snapshot_BipartiteM2.txt"));
    System.setOut(o);
    
      Iterator<String> iter = new DepthFirstIterator<>(randomBipartiteGraph);
      while (iter.hasNext()) {
          String vertex = iter.next();
          System.out.println(	
              "Vertex " + vertex + " is connected to: "
                  + randomBipartiteGraph.edgesOf(vertex).toString());
               }   
        }
   }



