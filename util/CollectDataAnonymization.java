package util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;


public abstract class CollectDataAnonymization {

	
	public static void main(String[] args) throws IOException {
		collectData();
	}
	
	public static void collectData() throws IOException {
		//File root = new File("./attackers-2/"); 
		//File root = new File("./attackers-4/"); 
		//File root = new File("./attackers-8/"); 
		//File root = new File("./attackers-16/");
		int numberOfVertices = 50;
		int[] attackers = new int[]{4};
		//int[] attackers = new int[]{1, 2, 4, 8, 16};
		List<TreeMap<Double, Double>> percentage = new LinkedList<>();
		for (int i = 0; i < attackers.length; i++){
			int numberOfAttackers = attackers[i];
			//File root = new File("./attackers-"+numberOfAttackers+"-"+numberOfVertices+"/"); 
			//File root = new File("./attackers-"+numberOfAttackers+"/"); 
			File root = new File("./attackers-"+numberOfVertices+"-"+numberOfAttackers+"/"); 
			List<File> files = getFiles(root);
			Hashtable<String, TreeMap<Pair, List<Result>>> result = new Hashtable<>();
			Hashtable<String, String> methodNames = new Hashtable();
			for (File f : files) {
				String fileName = f.getName();
				String[] split = fileName.split("(-|\\.DAT)");
				String name = split[0];
				methodNames.put(name, name);
			}
			for (String name : methodNames.keySet()){
				TreeMap<Pair, List<Result>>  data = collectDataByDensity(files, name);
				computeAverage(data, name, numberOfVertices, numberOfAttackers);
				//percentage[i] = computeDensityPercentage("CPA", data, densityScale, 3);
				percentage.add(computeEdgeRemoval("CPA", data, 1));
				
			}
		}
		/*FileWriter latexTableWriter = new FileWriter(new File("percentage-table.tex"));
		Latex.appendTableHeader(percentage, attackers, latexTableWriter);
		Latex.appendData(percentage, attackers, latexTableWriter);
		Latex.appendTableFooter(latexTableWriter);
		latexTableWriter.close();*/
		//printTable(basis, "basis.DAT");
		//printTable(resolving, "resolving.DAT");
	}

	private static TreeSet<Double> getDensityScale() {
		TreeSet<Double> result = new TreeSet<>();
		result.add(0.0);
		result.add(0.025);
		result.add(0.05);
		result.add(0.075);
		result.add(0.1);
		result.add(0.125);
		result.add(0.15);
		result.add(0.175);
		result.add(0.2);
		result.add(0.225);
		result.add(0.25);
		result.add(0.275);
		result.add(0.3);
		result.add(0.325);
		result.add(0.35);
		result.add(0.375);
		result.add(0.4);
		result.add(0.425);
		result.add(0.45);
		result.add(0.475);
		result.add(0.5);
		result.add(0.525);
		result.add(0.55);
		result.add(0.575);
		result.add(0.6);
		result.add(0.625);
		result.add(0.65);
		result.add(0.675);
		result.add(0.7);
		result.add(0.725);
		result.add(0.75);
		result.add(0.775);
		result.add(0.8);
		result.add(0.825);
		result.add(0.85);
		result.add(0.875);
		result.add(0.9);
		return result;
	}

	static class Pair implements Comparable{
		public int numberOfVertices; 
		public int numberOfAttackers; 
		public double density;
		
		public Pair(int numberOfVertices, int numberOfAttackers, double density) {
			super();
			this.numberOfVertices = numberOfVertices;
			this.numberOfAttackers = numberOfAttackers;
			this.density = density;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof Pair){
				Pair p = (Pair)obj;
				return 
						//this.numberOfAttackers == p.numberOfAttackers &&
						//this.numberOfVertices == p.numberOfVertices &&
						this.density == p.density;
			}
			return false;
		}

		@Override
		public int compareTo(Object o) {
			Pair tmp = (Pair)o;
			if (density < tmp.density) return -1;
			else if (density == tmp.density) return 0;
			else return 1;
		}
	}
	
	public static class Ratio{
		TreeMap<Pair, Double> positive;
		TreeMap<Pair, Double> negative;
		TreeMap<Pair, Double> unknown;
		public Ratio(TreeMap<Pair, Double> positive, TreeMap<Pair, Double> negative, 
				TreeMap<Pair, Double> unknown){
			this.positive = positive;
			this.negative = negative;
			this.unknown = unknown;
		}
		
	}
	
	public static class Result{
		double k;
		double density;
		double diameter;
		double connectivity;
		double successRate;
		double percetangeDensityDistortion;
		double expectedDensity;
		double removedEdges;
		double removedEdgesUpperBound;
		
		public Result(double k, double density, double diameter, double connectivity,
				double successRate, double percetangeDensityDistortion,double expectedDensity, 
				double removedEdges, double removedEdgesUpperBound) {
			super();
			this.k = k;
			this.density = density;
			this.diameter = diameter;
			this.connectivity = connectivity;
			this.successRate = successRate;
			this.percetangeDensityDistortion = percetangeDensityDistortion;
			this.expectedDensity = expectedDensity;
			this.removedEdges = removedEdges;
			this.removedEdgesUpperBound = removedEdgesUpperBound;
		}
		
		
	}

	public static class ResultAvg{
		Result data;
		int numberOfSamples; 
		public ResultAvg(Result data, int numberOfSamples) {
			super();
			this.data = data;
			this.numberOfSamples = numberOfSamples;
		}
		
		
	}
	private static void computeAverage(TreeMap<Pair, List<Result>> data, String name, 
			int numberOfVertices, int numberOfAttackers) throws IOException {
		String fileName = name+"Average"+"-n-"+numberOfVertices+"-att-"+numberOfAttackers+".DAT";
		File outFile = new File(fileName);
		BufferedWriter writer = new BufferedWriter(new FileWriter(outFile, false));
		writer.write("#DENSITY \t TOTAL-SAMPLES \t FAILED-K \t k \t diameter \t connectivity \t successRate \t densityDistortion");
		writer.newLine();
		for (Pair key : data.keySet()) {
			if (key.numberOfAttackers != numberOfAttackers) throw new IllegalArgumentException();
			if (key.numberOfVertices != numberOfVertices) throw new IllegalArgumentException();
			double averageDegree = 0;
			double k = 0;
			double diameter = 0;
			double connectivity = 0;
			double successRate = 0;
			double densityDistortion = 0;
			double density = 0;
			double removedEdges = 0;
			double removedEdgesUpperBound = 0;
			double maximum = 0;
			int totalFailedK = 0;
			int totalRows = data.get(key).size();
			int n = numberOfVertices+numberOfAttackers;
			for (Result r : data.get(key)){
				if (r.k == -1) totalFailedK++;
				else k += r.k;
				diameter += r.diameter/totalRows;
				connectivity += r.connectivity/totalRows;
				successRate += r.successRate/totalRows;
				densityDistortion += r.percetangeDensityDistortion/totalRows;
				density += r.density/totalRows;
				removedEdges += r.removedEdges/totalRows;
				removedEdgesUpperBound += r.removedEdgesUpperBound/totalRows;
			}
			double originalDensity = density+densityDistortion;
			maximum = ((double)(n)*(n-1)*(1-originalDensity)/2);
			averageDegree = originalDensity*(n-1);

			double kRatio = (totalFailedK == 0)?k/totalRows:k/totalFailedK;
			writer.write(key.density+" \t "+totalRows+" \t "+
					totalFailedK+" \t "+kRatio+" \t "+
					diameter+" \t "+connectivity+" \t "+
					successRate + " \t "+densityDistortion+ 
					" \t "+removedEdges+" \t "+removedEdgesUpperBound+
					" \t "+maximum+" \t "+averageDegree);
			writer.newLine();
		}
		writer.close();
	}

	private static void computeAveragePerDegreeAverage(TreeMap<Pair, List<Result>> data, String name, 
			int numberOfVertices, int numberOfAttackers) throws IOException {
		String fileName = name+"Average-degree"+"-n-"+numberOfVertices+"-att-"+numberOfAttackers+".DAT";
		File outFile = new File(fileName);
		BufferedWriter writer = new BufferedWriter(new FileWriter(outFile, false));
		writer.write("#DENSITY \t TOTAL-SAMPLES \t FAILED-K \t k \t diameter \t connectivity \t successRate \t densityDistortion");
		writer.newLine();
		for (Pair key : data.keySet()) {
			if (key.numberOfAttackers != numberOfAttackers) throw new IllegalArgumentException();
			if (key.numberOfVertices != numberOfVertices) throw new IllegalArgumentException();
			double averageDegree = 0;
			double k = 0;
			double diameter = 0;
			double connectivity = 0;
			double successRate = 0;
			double densityDistortion = 0;
			double density = 0;
			double removedEdges = 0;
			double removedEdgesUpperBound = 0;
			double maximum = 0;
			int totalFailedK = 0;
			int totalRows = data.get(key).size();
			int n = numberOfVertices+numberOfAttackers;
			for (Result r : data.get(key)){
				if (r.k == -1) totalFailedK++;
				else k += r.k;
				diameter += r.diameter/totalRows;
				connectivity += r.connectivity/totalRows;
				successRate += r.successRate/totalRows;
				densityDistortion += r.percetangeDensityDistortion/totalRows;
				density += r.density/totalRows;
				removedEdges += r.removedEdges/totalRows;
				removedEdgesUpperBound += r.removedEdgesUpperBound/totalRows;
			}
			maximum = ((double)(n)*(n-1)*(1-density));
			averageDegree = density*(n-1);
			
			double kRatio = (totalFailedK == 0)?k/totalRows:k/totalFailedK;
			writer.write(key.density+" \t "+totalRows+" \t "+
					totalFailedK+" \t "+kRatio+" \t "+
					diameter+" \t "+connectivity+" \t "+
					successRate + " \t "+densityDistortion+ 
					" \t "+removedEdges+" \t "+removedEdgesUpperBound+
					" \t "+maximum);
			writer.newLine();
		}
		writer.close();
	}

	private static double[] computeDensityPercentage(String name, Hashtable<String, TreeMap<Pair, List<Result>>> allData, 
			TreeSet<Double> densityScale, int significantDigits) throws IOException {
		TreeMap<Double, Double> percentage = new TreeMap<>();
		TreeMap<Pair, List<Result>> data = allData.get(name);
		for (Pair key : data.keySet()) {
			int totalRows = data.get(key).size();
			double densityDistortion = 0;
			for (Result r : data.get(key)){
				densityDistortion += r.percetangeDensityDistortion;
			}
			if (percentage.containsKey(key.density))
				throw new RuntimeException();
			else percentage.put(key.density, densityDistortion/totalRows);
		}
		double[] result = new double[percentage.size()];
		int pos = 0;
		for (Double den : percentage.values()){
			result[pos++] = (int)(den*Math.pow(10, significantDigits))/Math.pow(10, significantDigits);
		}
		return result;
	}

	private static TreeMap<Double, Double> computeEdgeRemoval(String name, TreeMap<Pair, List<Result>> data, 
			int significantDigits) throws IOException {
		TreeMap<Double, Double> percentage = new TreeMap<>();
		for (Pair key : data.keySet()) {
			int totalRows = data.get(key).size();
			double densityDistortion = 0;
			for (Result r : data.get(key)){
				densityDistortion += r.percetangeDensityDistortion;
			}
			//double edgeOriginal = (key.density)*key.numberOfVertices*(key.numberOfVertices-1)/2;
			//double edgeResulting = (densityDistortion/totalRows)*key.numberOfVertices*(key.numberOfVertices-1)/2;
			double edgeRemoval  = (densityDistortion/totalRows)*key.numberOfVertices*(key.numberOfVertices-1)/2;
			edgeRemoval = ((int)((edgeRemoval)*Math.pow(10, significantDigits)))/Math.pow(10, significantDigits);
			if (percentage.containsKey(key.density))
				throw new RuntimeException();
			else percentage.put(key.density, edgeRemoval);
		}
		return percentage;
	}

	private static TreeMap<Pair, List<Result>> collectDataByDensity(List<File> files, String methodName) throws IOException {
		TreeMap<Pair, List<Result>> result = new TreeMap();
		//Hashtable<String, TreeMap<Pair, List<Result>>> result = new Hashtable<>();
		int numberOfVertices;
		int numberOfAttackers;
		double k;
		double density;
		double diameter;
		double connectivity;
		double successRate;
		double removedEdges;
		double removedEdgesUpperBound;
		
		for (File f : files) {
			String fileName = f.getName();
			String[] split = fileName.split("(-|\\.DAT)");
			String name = split[0];
			if (!name.equals(methodName)) continue;
			numberOfVertices = Integer.parseInt(split[2]);
			double expectedDensity = Double.parseDouble(split[4]);//this is the expected density
			numberOfAttackers = Integer.parseInt(split[6]);
			BufferedReader reader = new BufferedReader(new FileReader(f));
			String line = reader.readLine();
			int totalRows = 0;
			while(line != null){
				String[] data = line.split(" \\t ");
				//first column (data[0]) is just the index and it can be safely ignored
				k = Integer.parseInt(data[1]);
				//data[2] is also skip because it gives the number of vertices
				if (Integer.parseInt(data[2]) != numberOfVertices+numberOfAttackers) 
					throw new RuntimeException("The number of nodes in the parsed file is "+Integer.parseInt(data[2])+
							" while we were expecting +"+numberOfVertices+" original vertices plus "+numberOfAttackers+" attackers");
				density = Double.parseDouble(data[3]);
				//now we look for the closer scale to realDensity
				//double percetangeDensityDistortion = density - expectedDensity;
				double percetangeDensityDistortion = Double.parseDouble(data[7]);
				diameter = Double.parseDouble(data[4]);
				connectivity = Double.parseDouble(data[5]);
				successRate = Double.parseDouble(data[6]);
				removedEdges = Double.parseDouble(data[8]);
				removedEdgesUpperBound = Double.parseDouble(data[9]);
				/*Trujillo- Feb 9, 2016
				 * Next we identify the Pair (numberOfVertices, numberOfAttacker, density)
				 * and add the corresponding result*/
				/*Trujillo- Mar 2, 2016
				 * We will organized in terms of the expected density rather than on the actual density.
				 * That is to say, we will organize in terms of the density of the original graph, not
				 * on the density of the anonymized graph*/
				Pair newPair = new Pair(numberOfVertices, numberOfAttackers, expectedDensity);
				//Pair newPair = new Pair(numberOfVertices, numberOfAttackers, expectedDensity);
				Result row = new Result(k, density, diameter, connectivity, successRate, percetangeDensityDistortion, 
						expectedDensity, removedEdges, removedEdgesUpperBound);
				if (!result.containsKey(newPair)){
					result.put(newPair, new LinkedList<Result>());
				}
				result.get(newPair).add(row);
				line = reader.readLine();
				totalRows++;
			}
			System.out.println("For the file "+fileName+" we counted "+totalRows+" rows");
		}
		return result;
	}

	private static List<File> getFiles(File root) {
		return getFiles(root, ".DAT");
	}
	private static List<File> getFilesSet(File root) {
		return getFiles(root, "output-k");
	}
	
	private static List<File> getFiles(File root, String pattern) {
		File[] files = root.listFiles();
		List<File> result = new LinkedList<>();
		if (files == null) return result;
		List<File> tmp = null;
		for (int i = 0; i < files.length; i++) {
			if (files[i].isDirectory()){
				tmp = getFiles(files[i], pattern);
				result.addAll(tmp);
			}
			else{
				if (files[i].getName().contains(pattern)){
					result.add(files[i]);
				}
			}
		}
		return result;
	}
}
