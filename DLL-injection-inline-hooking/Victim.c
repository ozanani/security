#include <stdio.h>
#include <Windows.h>

int main()
{
	char pass[20];

	printf("What's the password?\n");
	scanf("%s", pass);

	if (lstrcmpA(pass, "Y3liZXI=\n") == 0)
		printf("\nPassword is correct.");
	
	else
		printf("\nYou have failed again...");

	_getch();
	return 0;
}