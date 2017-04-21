import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



public class ASGraph {
	public static Map asn_table = new HashMap();
	public static Map asn_owners = new HashMap();
	public static Map<Long, String> geo_table = new HashMap();
	public static Map<String, List<String>> ASprobes = new HashMap();
	public static Map<String, List> pathGeo = new HashMap();

	public static Map<String, Map> probePaths = new HashMap();

	public static Map<String, Map<String, Set>> relationships = new HashMap();
	public static Map<String, Integer> asrelcount = new HashMap();

	static Random r = new Random();


	public static void main(String [] args) throws IOException {
		loadList();

		// Loading list of traceroute outputs
		loadGeolocation("GeoLite2-City-Blocks-IPv4.csv");
		loadTraceroutes("/tmp/results_nov.dat"); // /tmp/result_large.dat");


		Set<String> allTimestamps = new HashSet();

		// Find all timestamps that are in the data set
		for(String as : probePaths.keySet()) {
			allTimestamps.addAll(probePaths.get(as).keySet());
		}
		List<String> allTimestamps_ordered = new ArrayList(allTimestamps);
		Collections.sort(allTimestamps_ordered);

		int[] sums = new int[allTimestamps_ordered.size()];

		System.out.println(probePaths.size()+" with probes in it, "+allTimestamps_ordered.size()+" time intervals.");


		// Get adj list
		System.out.print("Probe,");
		for(String time : allTimestamps_ordered)			System.out.print(time+",");
		System.out.println();
		Map<String, Set> lastASMapping = new HashMap();

		for(String probe : probePaths.keySet()) {
			Map<String, Path> probePath = probePaths.get(probe);
			Path lastPath = null;
			int t = 0;

			Set<String> normalUpstream = new HashSet();
			System.out.print(probe+"("+probePath.size()+"),");

			Set<Node> ASnodes = new HashSet();
			Map<String, Integer> ASlinkCounts = new HashMap();


			for(String time : allTimestamps_ordered) {
				t++;

				// Entry does not exist
				if(!probePath.containsKey(time)) {
					System.out.print("_,");
					continue;
				}

				int diff = 0;

				Path path = (Path) probePath.get(time);
				if(path!=null && lastPath!=null) {
					// Analyze degree of differences

					// Case 1: Path is not identical, value code = 1
					List<String> compactLastASPath = new ArrayList();
					List<String> compactASPath = new ArrayList();
					for(int i=0; i<lastPath.size(); i++) {
						if(lastPath.get(i).getASN()==null) continue;
						String asn = lastPath.get(i).getASN();
						if(compactLastASPath.size()==0 || !compactLastASPath.get(compactLastASPath.size()-1).equals(asn))
							compactLastASPath.add(asn);
					}
					for(int i=0; i<path.size(); i++) {
						if(path.get(i).getASN()==null) continue;
						String asn = path.get(i).getASN();
						if(compactASPath.size()==0 || !compactASPath.get(compactASPath.size()-1).equals(asn))
							compactASPath.add(asn);
						ASnodes.add(path.get(i));
					}

					if(compactLastASPath.size()!=compactASPath.size()) {
						diff += 1;
					}else{

						for(int i=0; i<compactLastASPath.size(); i++) {
							if(!compactLastASPath.get(i).equals(compactASPath.get(i))) {
								diff += 1;
								break;
							}
						}
					}

					for(int i=0; i<compactASPath.size()-1; i++) {
						String aslink = compactASPath.get(i)+","+compactASPath.get(i+1);

						if(!ASlinkCounts.containsKey(aslink)) ASlinkCounts.put(aslink, 0);
						ASlinkCounts.put(aslink, 1 + ASlinkCounts.get(aslink));
					}


					// Case 2: Upstream provider is something not seen before
					if(path.size()>=2) {
						String upstream = ((Node) path.get(1)).getASN();
						if(!normalUpstream.contains(upstream)) diff += 2;
					}


				}

				if(path!=null && path.size()>=2) {
					Node n = ((Node) path.get(1));
					if(n!=null && n.getASN()!=null && normalUpstream!=null) 
						normalUpstream.add(n.getASN());
				}

				lastPath = path;
				System.out.print(diff+",");

				if(diff>0 && sums.length>t) sums[t]++;
			}

			System.out.println();


			// Sample a small number of probes to display
			if(r.nextInt(50)==0) {
				Set<String> asn = new HashSet();

				BufferedWriter bw = new BufferedWriter(new FileWriter("/tmp/network"+probe+"-nodes.csv"));
				bw.append("Node,latitude,longitude,color\n");
				for(Path path : probePath.values()) {
					for(Node n : path.getPath()) { 
						if(!asn.contains(n.getASN())) {
							bw.append(n.getASN()+","+n.getLatLon()+","+n.getASN()+"\n");
							asn.add(n.getASN());
						}
					}
				}
				bw.close();

				bw = new BufferedWriter(new FileWriter("/tmp/network"+probe+"-edges.csv"));
				bw.append("from,to,weight,color\n");
				for(String link : ASlinkCounts.keySet()) {
					String color = "500";

					// Show the last iteration in comparison to historical record of route paths
					for(int i=0; i<lastPath.getPath().size()-1; i++) {
						String pathLink = lastPath.get(i).getASN()+","+lastPath.get(i+1).getASN();
						if(link.equals(pathLink)) color = "10000";
					}

					bw.append(link+","+ASlinkCounts.get(link)+","+color+"\n");
				}
				bw.close();
			}


		}

		System.out.print("Sum,");
		for(int i=0; i<sums.length; i++)
			System.out.print(sums[i]+",");
		System.out.println();

	}

	
	public static String lookupGeo(String ip) {
		long ipaddr = ip2long(ip);

		for (int i=0; i<32; i++) {
			long ip2 = (ipaddr >> i) << i;

			if(geo_table.containsKey(ip2)) {
				return geo_table.get(ip2);
			}
		}
		return null;
	}


	public static void loadGeolocation(String file) throws IOException {
		String line;
		BufferedReader br = new BufferedReader(new FileReader(file));
		br.readLine();
		while((line = br.readLine()) != null) {
			String [] elements = line.split(",");

			try {
				int pos = elements[0].indexOf("/");
				String w = elements[0].substring(0, pos);
				geo_table.put(ip2long(w), elements[7]+","+elements[8]);
			}catch(Exception e) {}
		}
		br.close();
	}

	public static boolean setsEqual(Set a, Set b) {
		if(a.size()!=b.size()) return false;

		for(Object o : a) {
			if(!b.contains(o)) return false;
		}
		return true;
	}


	public static void loadTraceroutes(String traceroutes) throws IOException {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd-HH");

		String line, last, aslast;
		BufferedReader br = new BufferedReader(new FileReader(traceroutes));
		while((line = br.readLine()) != null) {
			String probeID = line;
			last = br.readLine();

			// Sometimes, the probes are not responding with a valid entry
			if(last.length()==0) {
				while((line = br.readLine())!=null)
					if(line.equals(".")) break;

				continue;
			}

			aslast = (String) lookup(last).get("asn");
			String time = sdf.format(new Date(Long.parseLong(br.readLine())*1000L));

			if(!ASprobes.containsKey(aslast)) ASprobes.put(aslast, new ArrayList());
			ASprobes.get(aslast).add(probeID);


			Path path = new Path();


			while((line = br.readLine())!=null) {
				if(line.equals(".")) break;
				if(line.equals("*")) continue;

				String ipas = null, nextip = line.substring(3);
				try {
					if(line.startsWith("IP:")) {
						ipas = (String) lookup(nextip).get("asn");
					}else
						ipas = nextip;
				}catch(Exception e) {
					// This means we have encountered an IP address that is not a valid allocation
					// We ignore these for now
					continue;
				}

				path.add(nextip);
			}

			if(!probePaths.containsKey(probeID)) probePaths.put(probeID, new HashMap());
			probePaths.get(probeID).put(time, path);			
		}
		br.close();

	}


	public static Map lookup(String ip) {
		long ipaddr = ip2long(ip);

		for (int i=0; i<32; i++) {
			long ip2 = (ipaddr >> i) << i;
			if(asn_table.containsKey(ip2)) {
				String asn = (String) asn_table.get(ip2);

				Map result = new HashMap();
				result.put("asn", asn);
				result.put("ip", ip);

				if(asn_owners.containsKey(asn))
					result.put("asname", asn_owners.get(asn));

				return result;
			}
		}

		return null;
	}

	public static void loadList() throws IOException {
		String line;
		Pattern p = Pattern.compile("([0-9.]+)/\\d+\\s+(\\d+)");

		try {
			BufferedReader br = new BufferedReader(new FileReader("data-raw-table"));
			while((line = br.readLine()) != null) {
				Matcher m = p.matcher(line);
				if(m.find()) {
					asn_table.put(ip2long(m.group(1)), m.group(2));
				}
			}
			br.close();
		}catch(FileNotFoundException e) {
			System.out.println("Data file not found. Please download http://thyme.apnic.net/current/data-raw-table");
			System.exit(-1);
		}

		try {
			p = Pattern.compile("\\s*(\\d+)\\s+(.*)");
			BufferedReader br = new BufferedReader(new FileReader("data-used-autnums"));
			while((line = br.readLine()) != null) {
				Matcher m = p.matcher(line);
				if(m.find())
					asn_owners.put(m.group(1), m.group(2));
			}
			br.close();
		}catch(FileNotFoundException e) {
			System.out.println("Data file not found. Please download http://thyme.apnic.net/current/data-used-autnums");
			System.exit(-1);
		}
	}

	public static long ip2long(String ipAddress) {
		long result = 0;
		String[] ipAddressInArray = ipAddress.split("\\.");

		for (int i = 3; i >= 0; i--) {
			long ip = Long.parseLong(ipAddressInArray[3 - i]);
			result |= ip << (i * 8);
		}
		return result;
	}
}

class Path {
	List<Node> path = new ArrayList();

	public void add(String IP) {
		this.path.add(new Node(IP));
	}

	public List<Node> getPath() { return path; }
	public int size() { return path.size(); }
	public Node get(int i) { return path.get(i); }

	public String toString() {
		StringBuffer b = new StringBuffer();
		for(Node n : path) {
			b.append(n.getIP()+"/AS"+n.getASN()+" -> ");
		}

		return b.toString();
	}
}

class Node {
	String ASN;
	String IP;
	String latlon;

	public Node(String IP) {
		this.IP = IP;

		try {
			Map ASN = ASGraph.lookup(IP);
			if(ASN!=null) this.ASN = (String) ASN.get("asn");

			String ll = ASGraph.lookupGeo(IP);
			if(ll!=null) this.latlon = ll;
		}catch(Exception e) {}
	}

	public String getASN() { return ASN; }
	public String getIP() { return IP; }
	public String getLatLon() { return latlon; }

	public int hashCode() {
		return IP.hashCode();
	}

	public boolean equals(Object o){
		if(!(o instanceof Node)) return false;

		return ((Node)o).getIP().equals(IP);
	}
}
