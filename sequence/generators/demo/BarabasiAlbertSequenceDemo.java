package sequence.generators.demo;

import java.io.IOException;
import org.jgrapht.graph.DefaultEdge;

import enterprise.sequence.generators.BarabasiAlbertSequenceGenerator;

public class BarabasiAlbertSequenceDemo {
	
	public static void main(String[] args) throws IOException {
		
	    BarabasiAlbertSequenceGenerator<String, DefaultEdge> generator = new BarabasiAlbertSequenceGenerator<String, DefaultEdge>(5, 3, 208, 5);
	    generator.initialize(1);        
	    generator.makeSnapshot(0);
	
	    
	}
}