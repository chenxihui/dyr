package enterprise.sequence.generators;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

public class Utils {

	public static void saveDegreesToFile(List<Integer> integers) throws IOException {
		try {
			FileWriter fileWriter = new FileWriter(new File("degrees.txt"));
	        BufferedWriter out = new BufferedWriter(fileWriter);
	        for (int number : integers) {
	            out.write(Integer.toString(number) + " \n");
	            out.newLine();
	        }
	        out.flush();
	        out.close();
		}finally {}
	}
		
	public static ArrayList<Integer> getDegreesFromFile(){
		ArrayList<Integer> integers = new ArrayList<Integer>();
		File file = new File("C:\\Users\\Ema\\eclipse-workspace\\NewGraph\\degrees.txt");
		try (BufferedReader br = new BufferedReader(new FileReader(file)))
        {
			Scanner scan = new Scanner(file);
            while (scan.hasNext()) {
                integers.add(scan.nextInt());
            }
            scan.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
		return integers;
	}
	
	public static void saveDegreeSum(int degreeSum) throws FileNotFoundException, IOException{
	    Properties prop = new Properties();
	    prop.setProperty("sum", Integer.toString(degreeSum));
	    prop.store(new FileOutputStream("file.properties"), null);
	}

	public static int getDegreeSum() throws FileNotFoundException, IOException{
	    Properties prop = new Properties();
	    prop.load(new FileInputStream("file.properties"));
	    int degreeSum = Integer.parseInt(prop.getProperty("sum"));
	    return degreeSum;
	}
	
	public static SimpleGraph<String, DefaultEdge> cloneGraph(SimpleGraph<String, DefaultEdge> graph) {
		SimpleGraph<String, DefaultEdge> result = new SimpleGraph<>(DefaultEdge.class);
		for (String v : graph.vertexSet()){
			result.addVertex(v);
		}
		for (String v1 : graph.vertexSet()){
			for (String v2 : graph.vertexSet()){
				if (graph.containsEdge(v1, v2))
					result.addEdge(v1, v2);
			}
		}
		return result;
	}
}
